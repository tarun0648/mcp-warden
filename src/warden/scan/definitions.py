"""Scanning upstream tool *definitions*.

A tool definition is the attacker's cheapest channel: it reaches the model on every
`tools/list`, before any call is made, and nothing the user does invites it. So every part of
it is scanned - the name, the description, every description inside the input schema, and the
annotations - not just the top-level description, because `inputSchema.properties.city.
description` is read by the model exactly as eagerly.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from mcp_types import Tool

from warden.audit.chain import canonical_json, sha256_text
from warden.config import ScanConfig
from warden.scan.classifier import ClassifierResult, InjectionClassifier
from warden.scan.findings import Finding, ScanReport, Severity, score_findings
from warden.scan.text_rules import find_cross_tool_references, scan_text

#: How many characters of a tool's own name may be scanned; a name longer than this is itself
#: the finding.
MAX_NAME_CHARS = 128


def definition_hash(tool: Tool) -> str:
    """A stable fingerprint of a definition, used for pinning and rug-pull detection.

    Taken over the canonical JSON of the whole definition by alias, so a change anywhere -
    description, schema, annotations - changes the hash. `canonical_json` sorts keys, so the
    same definition serialised in a different order is the same pin.
    """
    return sha256_text(canonical_json(tool.model_dump(mode="json", by_alias=True)))


@dataclass(frozen=True, slots=True)
class DefinitionScan:
    """A scan of one tool definition."""

    server: str
    tool: str
    sha256: str
    report: ScanReport

    @property
    def namespaced(self) -> str:
        from warden.config import namespaced

        return namespaced(self.server, self.tool)

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.namespaced, "sha256": self.sha256, **self.report.as_dict()}


def _schema_texts(schema: Any, path: str = "inputSchema") -> Iterator[tuple[str, str]]:
    """Every human-readable string inside a JSON schema, with where it came from."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("description", "title", "default", "const") and isinstance(value, str):
                yield f"{path}.{key}", value
            elif key == "enum" and isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, str):
                        yield f"{path}.enum[{index}]", item
            else:
                yield from _schema_texts(value, f"{path}.{key}")
    elif isinstance(schema, list):
        for index, item in enumerate(schema):
            yield from _schema_texts(item, f"{path}[{index}]")


def definition_texts(tool: Tool) -> list[tuple[str, str]]:
    """Every piece of attacker-controlled text in a definition, labelled by location."""
    texts: list[tuple[str, str]] = [("name", tool.name[:MAX_NAME_CHARS])]
    if tool.title:
        texts.append(("title", tool.title))
    if tool.description:
        texts.append(("description", tool.description))
    texts.extend(_schema_texts(tool.input_schema))
    if tool.output_schema:
        texts.extend(_schema_texts(tool.output_schema, "outputSchema"))
    if tool.annotations is not None:
        annotations = tool.annotations.model_dump(mode="json", by_alias=True)
        texts.extend(_schema_texts(annotations, "annotations"))
    if tool.meta:
        texts.extend(_schema_texts(tool.meta, "_meta"))
    return texts


class DefinitionScanner:
    """Runs the rules, and optionally the classifier, over tool definitions."""

    def __init__(self, config: ScanConfig, classifier: InjectionClassifier | None = None) -> None:
        self._config = config
        self._classifier = classifier

    async def scan(
        self,
        tool: Tool,
        *,
        server: str,
        other_servers: Iterable[str] = (),
        other_tools: Iterable[str] = (),
    ) -> DefinitionScan:
        """Scan one definition and return its verdict."""
        findings: list[Finding] = []
        for where, text in definition_texts(tool):
            limit = (
                self._config.max_definition_description_chars
                if where in ("description", "title")
                else None
            )
            findings.extend(scan_text(text, where=where, length_limit=limit))
            findings.extend(
                find_cross_tool_references(
                    text,
                    own_server=server,
                    other_servers=other_servers,
                    other_tools=other_tools,
                    where=where,
                )
            )

        classifier_score: float | None = None
        if self._classifier is not None and self._classifier.enabled:
            result = await self._classify(tool)
            classifier_score = result.score
            findings.extend(self._classifier_findings(result))

        report = score_findings(
            findings,
            suspicious_at=self._config.definition_suspicious_score,
            malicious_at=self._config.definition_malicious_score,
            classifier_score=classifier_score,
        )
        return DefinitionScan(
            server=server, tool=tool.name, sha256=definition_hash(tool), report=report
        )

    async def _classify(self, tool: Tool) -> ClassifierResult:
        assert self._classifier is not None
        joined = "\n".join(text for _where, text in definition_texts(tool) if text)
        return await self._classifier.classify(joined)

    def _classifier_findings(self, result: ClassifierResult) -> list[Finding]:
        """A confident classifier hit is strong evidence; a failure is weak but recorded.

        A classifier error does not quarantine a tool on its own: a model that will not load
        must not take every upstream offline. It is recorded so an operator can see that the
        verdict was reached by rules alone.
        """
        if result.failed:
            return [
                Finding(
                    rule="classifier:error",
                    severity=Severity.LOW,
                    evidence=result.error or "unknown error",
                    where="definition",
                )
            ]
        if result.exceeds(self._config.classifier_threshold):
            return [
                Finding(
                    rule="classifier:injection",
                    severity=Severity.HIGH,
                    evidence=f"injection probability {result.score:.3f}",
                    where="definition",
                )
            ]
        return []


def diff_definitions(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """A readable field-by-field diff, for `warden tools diff`.

    Values are rendered with `excerpt`, so a diff of a poisoned description cannot itself
    smuggle control characters into the operator's terminal.
    """
    from warden.scan.findings import excerpt

    lines: list[str] = []
    for key in sorted(set(old) | set(new)):
        before = old.get(key)
        after = new.get(key)
        if before == after:
            continue
        lines.append(f"{key}:")
        lines.append(f"  - {excerpt(_render(before), limit=300)}")
        lines.append(f"  + {excerpt(_render(after), limit=300)}")
    return lines


def _render(value: Any) -> str:
    if value is None:
        return "(absent)"
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


__all__ = [
    "DefinitionScan",
    "DefinitionScanner",
    "definition_hash",
    "definition_texts",
    "diff_definitions",
]
