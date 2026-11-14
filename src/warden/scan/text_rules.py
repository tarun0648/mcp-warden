"""The rules that read untrusted text, shared by the definition and output scanners.

Every rule here is deliberately *specific*. The failure mode for a prompt-injection detector is
not missing an attack - the classifier and the policy are there for that - it is firing on
ordinary English and training everyone to ignore it. So:

* "ignore" alone is not a signal. "ignore all previous instructions" is.
* "password" alone is not a signal; a password *policy* note is a perfectly normal document.
  "~/.ssh/id_rsa" is.
* "system" alone is not a signal. "system prompt" is.

Each rule has at least three positive and three negative examples in
`tests/unit/test_scan_text_rules.py`, and the negatives are drawn from the seeded notes and tool
descriptions this project actually ships.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Final

from warden.scan.findings import Finding, Severity, excerpt

# ----------------------------------------------------------------------------------------------
# Invisible and direction-changing characters
# ----------------------------------------------------------------------------------------------

#: Characters that are invisible, change reading order, or carry hidden data. A human reading a
#: tool description sees nothing; a model reading the raw string sees everything.
INVISIBLE_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x200B, 0x200F),  # zero-width space/non-joiner/joiner, LRM, RLM
    (0x202A, 0x202E),  # bidi embedding and override
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # byte-order mark used mid-string
    (0xE0000, 0xE007F),  # tag characters: a whole hidden alphabet
)

BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)


def _is_invisible(char: str) -> bool:
    code = ord(char)
    return any(low <= code <= high for low, high in INVISIBLE_RANGES)


def find_invisible_characters(text: str, where: str = "") -> list[Finding]:
    """Flag invisible, bidi and tag characters, naming each one found."""
    found = {char for char in text if _is_invisible(char)}
    if not found:
        return []
    names = ", ".join(
        f"U+{ord(char):04X} ({unicodedata.name(char, 'unnamed')})" for char in sorted(found)
    )
    severity = Severity.HIGH if found & BIDI_CONTROLS else Severity.MEDIUM
    return [
        Finding(
            rule="invisible_unicode",
            severity=severity,
            evidence=f"{len([c for c in text if _is_invisible(c)])} hidden character(s): {names}",
            where=where,
        )
    ]


def strip_invisible(text: str) -> str:
    """The text as a human sees it, for rules that should not be fooled by `i\u200bgnore`."""
    return "".join(char for char in text if not _is_invisible(char))


# ----------------------------------------------------------------------------------------------
# Instruction-like phrases
# ----------------------------------------------------------------------------------------------

#: (rule suffix, weight, pattern). Patterns run against the *invisible-stripped*, lowercased,
#: whitespace-collapsed text, so `i<ZWSP>gnore all previous instructions` still matches.
INSTRUCTION_PATTERNS: Final[tuple[tuple[str, int, re.Pattern[str]], ...]] = (
    (
        "override_instructions",
        Severity.HIGH,
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.!?]{0,40}?"
            # The determiner matters: it is what separates "disregard your instructions" from
            # "you can disregard the deprecation warning". The noun list does the rest.
            r"\b(?:all|any|the|your|these|those|my|its|previous|prior|earlier|above|"
            r"preceding|system)\b[^.!?]{0,40}?"
            r"\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)\b"
        ),
    ),
    (
        "important_block",
        Severity.HIGH,
        re.compile(r"<\s*/?\s*(?:important|system|admin|instructions?)\s*>"),
    ),
    (
        "conceal_from_user",
        Severity.HIGH,
        re.compile(
            r"\b(?:do not|don't|never|avoid)\b[^.!?]{0,30}?"
            # Stems with \w* so the gerund and the third person match too: "revealing",
            # "mentions", "notifying".
            r"\b(?:tell\w*|inform\w*|mention\w*|reveal\w*|disclos\w*|show\w*|notif\w*|say\w*)"
            r"[^.!?]{0,30}?"
            r"\b(?:user|human|operator|anyone)\b"
        ),
    ),
    (
        "before_other_tools",
        Severity.HIGH,
        re.compile(
            r"\bbefore\b[^.!?]{0,30}?\b(?:using|calling|invoking|you use|you call)\b"
            r"[^.!?]{0,30}?\btool"
        ),
    ),
    (
        "system_prompt",
        Severity.MEDIUM,
        re.compile(r"\b(?:system|initial|original)\s+prompt\b"),
    ),
    (
        "new_instructions",
        Severity.HIGH,
        re.compile(
            r"\b(?:new|updated|revised|real|actual)\s+"
            r"(?:instruction|instructions|task|directive|directives)"
            # Either punctuation introduces it ("New instructions: ...") or it is stated
            # ("Your real directive is to ...").
            r"\b[^.!?]{0,20}?(?:[:\-]|\s+is\s+to\b|\s+are\s+to\b)"
        ),
    ),
    (
        "authority_claim",
        Severity.MEDIUM,
        re.compile(
            r"\b(?:authorised|authorized|approved|requested|required)\b[^.!?]{0,25}?"
            r"\b(?:by the|by your)\b[^.!?]{0,25}?"
            r"\b(?:administrator|admin|system|developer|owner)\b"
        ),
    ),
    (
        # A deliberately small set of non-English equivalents of "ignore previous instructions".
        # This is not multilingual coverage and does not pretend to be: the local classifier is
        # the general answer, and the red-team report measures rules-only and rules+classifier
        # separately so the difference is visible rather than assumed.
        "override_instructions_non_english",
        Severity.HIGH,
        re.compile(
            r"\b(?:ignora|ignorez|ignoriere|ignorieren|ignora|esqueça|dimentica|"
            r"olvida|desconsidere|n[ae]gliger)\b[^.!?]{0,40}?"
            r"\b(?:instruc\w+|anweisung\w*|istruzion\w+|regras?|r[eè]gles?)\b"
        ),
    ),
    (
        "exfiltrate",
        Severity.HIGH,
        re.compile(
            r"\b(?:send|post|upload|exfiltrate|email|transmit|forward)\b[^.!?]{0,40}?"
            r"\b(?:contents?|file|files|secret|secrets|credentials?|key|keys|token|tokens|"
            r"environment|env)\b"
        ),
    ),
)


def normalise_for_matching(text: str) -> str:
    """Lowercase, invisible-stripped, whitespace-collapsed, NFKC-folded text.

    NFKC folds the lookalike forms - fullwidth letters, mathematical alphanumerics - that a
    naive lowercase misses.
    """
    folded = unicodedata.normalize("NFKC", strip_invisible(text))
    return " ".join(folded.lower().split())


def find_instruction_phrases(text: str, where: str = "") -> list[Finding]:
    """Flag phrasing that tries to steer a model rather than describe a tool."""
    haystack = normalise_for_matching(text)
    findings: list[Finding] = []
    for name, severity, pattern in INSTRUCTION_PATTERNS:
        match = pattern.search(haystack)
        if match is not None:
            findings.append(
                Finding(
                    rule=f"instruction:{name}",
                    severity=severity,
                    evidence=excerpt(match.group(0)),
                    where=where,
                )
            )
    return findings


# ----------------------------------------------------------------------------------------------
# Sensitive targets
# ----------------------------------------------------------------------------------------------

#: Things worth naming only if you intend to read them. A *path* or a *filename*, not a word:
#: "password policy" is a normal note, "~/.ssh/id_rsa" is not.
SENSITIVE_TARGET_PATTERNS: Final[tuple[tuple[str, int, re.Pattern[str]], ...]] = (
    (
        "ssh_key",
        Severity.HIGH,
        re.compile(r"(?:~|\$home|/home/[^/\s]+|/users/[^/\s]+)?/?\.ssh/|\bid_rsa\b|\bid_ed25519\b"),
    ),
    # `.env.example` is a file projects are *meant* to commit, this one included, so it is
    # excluded rather than reported on every scan of our own documentation.
    (
        "dotenv",
        Severity.MEDIUM,
        re.compile(r"(?:^|[\s/\"'=])\.env\b(?!\.(?:example|sample|template))"),
    ),
    ("private_key_header", Severity.CRITICAL, re.compile(r"-----begin [a-z ]*private key-----")),
    # "credentials" alone is ordinary English - "rotate credentials every 90 days" is a note
    # this project ships - so a file context is required: an extension, a directory, or the
    # literal word "file".
    (
        "credentials_file",
        Severity.MEDIUM,
        re.compile(
            r"\b(?:\.netrc|\.pgpass|id_dsa)\b"
            r"|\bcredentials\.(?:json|ya?ml|ini|txt|csv)\b"
            r"|[/\\]credentials\b"
            r"|\bcredentials\s+file\b"
        ),
    ),
    ("cloud_metadata", Severity.HIGH, re.compile(r"169\.254\.169\.254|metadata\.google\.internal")),
    ("shadow_file", Severity.HIGH, re.compile(r"/etc/(?:shadow|passwd|sudoers)")),
    ("keychain", Severity.MEDIUM, re.compile(r"\b(?:login\.keychain|secrets\.ya?ml|kubeconfig)\b")),
)


def find_sensitive_targets(text: str, where: str = "") -> list[Finding]:
    """Flag references to the specific files an attacker wants read."""
    haystack = normalise_for_matching(text)
    findings: list[Finding] = []
    for name, severity, pattern in SENSITIVE_TARGET_PATTERNS:
        match = pattern.search(haystack)
        if match is not None:
            findings.append(
                Finding(
                    rule=f"sensitive:{name}",
                    severity=severity,
                    evidence=excerpt(match.group(0)),
                    where=where,
                )
            )
    return findings


# ----------------------------------------------------------------------------------------------
# Encoded payloads, links and bulk
# ----------------------------------------------------------------------------------------------

BASE64_RE: Final = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
URL_RE: Final = re.compile(r"\bhttps?://[^\s<>\"')]{4,}", re.IGNORECASE)
MAX_DECODE_BYTES: Final = 64 * 1024


def find_base64_blobs(text: str, where: str = "") -> list[Finding]:
    """Flag long base64-looking runs. Decoding them is `decoded_segments`' job."""
    matches = BASE64_RE.findall(text)
    if not matches:
        return []
    longest = max(matches, key=len)
    return [
        Finding(
            rule="encoded:base64_blob",
            severity=Severity.LOW,
            evidence=f"{len(matches)} base64-looking run(s), longest {len(longest)} chars",
            where=where,
        )
    ]


def decoded_segments(text: str, *, limit: int = 8) -> Iterator[str]:
    """Yield the decoded text of each base64 run that decodes to printable text.

    Only printable results are yielded: random bytes that happen to decode are noise, while an
    instruction hidden in base64 is exactly what we are looking for. The rules are then run
    again over whatever comes out.
    """
    seen = 0
    for candidate in BASE64_RE.findall(text):
        if seen >= limit:
            return
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) > MAX_DECODE_BYTES:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for char in decoded if char.isprintable() or char in " \t\r\n")
        if len(decoded) >= 8 and printable / len(decoded) > 0.9:
            seen += 1
            yield decoded


def find_urls(text: str, where: str = "") -> list[Finding]:
    """Flag links. On their own they are weak evidence; next to an instruction they are not."""
    matches = URL_RE.findall(text)
    if not matches:
        return []
    return [
        Finding(
            rule="encoded:url",
            severity=Severity.LOW,
            evidence=f"{len(matches)} link(s), first {excerpt(matches[0], limit=60)}",
            where=where,
        )
    ]


def find_excessive_length(text: str, limit: int, where: str = "") -> list[Finding]:
    """Flag a description long enough to hide something in."""
    if len(text) <= limit:
        return []
    return [
        Finding(
            rule="bulk:too_long",
            severity=Severity.LOW,
            evidence=f"{len(text)} characters, over the limit of {limit}",
            where=where,
        )
    ]


# ----------------------------------------------------------------------------------------------
# Cross-tool references and shadowing
# ----------------------------------------------------------------------------------------------

REPLACEMENT_RE: Final = re.compile(
    r"\b(?:instead of|in place of|replaces?|replacement for|overrides?|supersedes?|"
    r"deprecat\w+|preferred over|faster than|rather than)\b"
)


def find_cross_tool_references(
    text: str,
    *,
    own_server: str,
    other_servers: Iterable[str],
    other_tools: Iterable[str],
    where: str = "",
) -> list[Finding]:
    """Flag a description that talks about another server's tools.

    A tool has no business naming a different server. Two separate signals:

    * a plain mention of another server or namespaced tool - suspicious;
    * a mention *plus* replacement language ("use this instead of files__read_file") - the
      shadowing attack, where a malicious server persuades the model to route calls to it.
    """
    haystack = normalise_for_matching(text)
    mentioned: list[str] = []
    for name in {*other_servers, *other_tools}:
        if not name or name == own_server:
            continue
        if re.search(rf"\b{re.escape(name.lower())}\b", haystack):
            mentioned.append(name)
    if not mentioned:
        return []
    named = ", ".join(sorted(mentioned)[:5])
    findings = [
        Finding(
            rule="cross_tool:mentions_another_server",
            severity=Severity.MEDIUM,
            evidence=f"names {named}",
            where=where,
        )
    ]
    replacement = REPLACEMENT_RE.search(haystack)
    if replacement is not None:
        findings.append(
            Finding(
                rule="cross_tool:claims_to_replace",
                severity=Severity.HIGH,
                evidence=f"'{excerpt(replacement.group(0), limit=40)}' while naming {named}",
                where=where,
            )
        )
    return findings


# ----------------------------------------------------------------------------------------------
# One pass over a piece of text
# ----------------------------------------------------------------------------------------------


def scan_text(
    text: str,
    *,
    where: str = "",
    length_limit: int | None = None,
    decode_base64: bool = True,
) -> list[Finding]:
    """Run every text rule over `text`, including over anything it has base64-encoded."""
    if not text:
        return []
    findings: list[Finding] = []
    findings.extend(find_invisible_characters(text, where))
    findings.extend(find_instruction_phrases(text, where))
    findings.extend(find_sensitive_targets(text, where))
    findings.extend(find_base64_blobs(text, where))
    findings.extend(find_urls(text, where))
    if length_limit is not None:
        findings.extend(find_excessive_length(text, length_limit, where))
    if decode_base64:
        for index, decoded in enumerate(decoded_segments(text)):
            nested = f"{where}.base64[{index}]" if where else f"base64[{index}]"
            # No further decoding: one layer is enough to catch the trick, and recursing on
            # attacker-controlled data is how a scanner becomes the denial of service.
            findings.extend(find_instruction_phrases(decoded, nested))
            findings.extend(find_sensitive_targets(decoded, nested))
    return findings


__all__ = [
    "BASE64_RE",
    "BIDI_CONTROLS",
    "INSTRUCTION_PATTERNS",
    "INVISIBLE_RANGES",
    "SENSITIVE_TARGET_PATTERNS",
    "URL_RE",
    "decoded_segments",
    "find_base64_blobs",
    "find_cross_tool_references",
    "find_excessive_length",
    "find_instruction_phrases",
    "find_invisible_characters",
    "find_sensitive_targets",
    "find_urls",
    "normalise_for_matching",
    "scan_text",
    "strip_invisible",
]
