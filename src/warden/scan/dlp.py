"""Looking for secrets in call arguments, before they leave the building.

This is the stage that stops the end of the tool-poisoning chain. The poisoned description
persuades the model to read `~/.ssh/id_rsa`; the policy may even allow reading files; the
exfiltration happens when the model passes what it read into an argument of some *other* tool.
DLP reads arguments on their way out and refuses the call.

Two classes of signal, weighted very differently:

* **Patterned secrets** - a private-key header, an AWS access key id, a JWT, a GitHub token,
  one of our own `wdn_` keys, a configured canary. These are unambiguous and deny on their own.
* **Generic high entropy** - a long, random-looking string. This is weak evidence and is
  weighted so it cannot deny by itself, because `files__write_file` content is legitimately
  arbitrary: a base64 image or a minified bundle is high-entropy and perfectly innocent.
  Weighting it to deny would make the gateway unusable for writing files, which is the kind of
  false positive that gets a security control switched off.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator, Sequence
from typing import Any, Final

from warden.scan.findings import Finding, ScanReport, Severity, score_findings

#: Longest argument value we scan. Beyond this the value is sampled: a 1 MB file body does not
#: need every byte read to find a key header, and an unbounded scan is a denial of service.
MAX_SCAN_CHARS: Final = 64 * 1024

#: (rule, weight, pattern). Each one identifies a specific credential format.
SECRET_PATTERNS: Final[tuple[tuple[str, int, re.Pattern[str]], ...]] = (
    (
        "private_key",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ),
    ("openssh_key", Severity.CRITICAL, re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("aws_access_key_id", Severity.CRITICAL, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        Severity.HIGH,
        re.compile(r"\baws_secret_access_key\b\s*[:=]\s*\S{20,}", re.IGNORECASE),
    ),
    ("github_token", Severity.CRITICAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_fine_grained", Severity.CRITICAL, re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("slack_token", Severity.CRITICAL, re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", Severity.CRITICAL, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai_key", Severity.CRITICAL, re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("stripe_key", Severity.CRITICAL, re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    #: Our own API keys. A model that has been handed one must not be able to post it anywhere.
    ("warden_api_key", Severity.CRITICAL, re.compile(r"\bwdn_[A-Za-z0-9_-]{32}\b")),
    (
        "jwt",
        Severity.HIGH,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "password_assignment",
        Severity.HIGH,
        # No leading \b: a word boundary does not exist between "db_" and "password", so
        # `db_password = ...` was slipping past. The keyword only has to *end* a name.
        re.compile(
            r"(?:password|passwd|secret|api[_-]?key|apikey|token|bearer)\s*[:=]\s*"
            r"[\"']?[^\s\"',;]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "postgres_url",
        Severity.HIGH,
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb)://[^\s:@/]+:[^\s@/]+@"),
    ),
)

#: Minimum length and Shannon entropy for the generic rule. 3.5 bits per character is roughly
#: where random base64 sits and ordinary prose does not.
MIN_ENTROPY_LENGTH: Final = 32
MIN_ENTROPY_BITS: Final = 3.5
#: Values under this many distinct characters are not random no matter how long they are.
MIN_ENTROPY_ALPHABET: Final = 12

_HIGH_ENTROPY_CANDIDATE: Final = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def describe_secret(value: str) -> str:
    """Evidence that identifies a secret without reproducing it.

    Four leading characters and a length is enough for an operator to recognise which key leaked
    and rotate it; it is not enough to use. Anything more would make the audit log and the logs
    a place secrets live, which is what hard rule 2 forbids.
    """
    head = value[:4]
    return f"{head}... ({len(value)} chars)"


def _walk(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (path, text) for every string anywhere in the argument structure."""
    if isinstance(value, str):
        yield path or "<root>", value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


def scan_value(text: str, where: str, canaries: Sequence[str] = ()) -> list[Finding]:
    """Run every DLP rule over one string."""
    sample = text[:MAX_SCAN_CHARS]
    findings: list[Finding] = []

    for canary in canaries:
        if canary and canary in sample:
            findings.append(
                Finding(
                    rule="dlp:canary",
                    severity=Severity.CRITICAL,
                    evidence=describe_secret(canary),
                    where=where,
                )
            )

    for name, severity, pattern in SECRET_PATTERNS:
        match = pattern.search(sample)
        if match is not None:
            findings.append(
                Finding(
                    rule=f"dlp:{name}",
                    severity=severity,
                    evidence=describe_secret(match.group(0)),
                    where=where,
                )
            )

    for candidate in _HIGH_ENTROPY_CANDIDATE.findall(sample):
        if (
            len(candidate) >= MIN_ENTROPY_LENGTH
            and len(set(candidate)) >= MIN_ENTROPY_ALPHABET
            and shannon_entropy(candidate) >= MIN_ENTROPY_BITS
        ):
            findings.append(
                Finding(
                    rule="dlp:high_entropy",
                    severity=Severity.LOW,
                    evidence=describe_secret(candidate),
                    where=where,
                )
            )
            break

    return findings


def scan_arguments(
    arguments: dict[str, Any],
    *,
    canaries: Sequence[str] = (),
    suspicious_at: int = 2,
    malicious_at: int = 5,
) -> ScanReport:
    """Scan every string in the arguments and return a report.

    The caller denies on `verdict != clean`: a single patterned secret is CRITICAL and so
    malicious on its own, while generic high entropy is LOW and needs company.
    """
    findings: list[Finding] = []
    for path, text in _walk(arguments):
        findings.extend(scan_value(text, path, canaries))
    return score_findings(findings, suspicious_at=suspicious_at, malicious_at=malicious_at)


__all__ = [
    "MAX_SCAN_CHARS",
    "MIN_ENTROPY_BITS",
    "MIN_ENTROPY_LENGTH",
    "SECRET_PATTERNS",
    "describe_secret",
    "scan_arguments",
    "scan_value",
    "shannon_entropy",
]
