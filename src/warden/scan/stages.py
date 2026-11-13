"""The three Phase 8 pipeline stages."""

from __future__ import annotations

from warden.config import ScanConfig, ServersConfig
from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import RequestContext
from warden.scan.dlp import scan_arguments
from warden.scan.output import OutputScanner, wrap_result
from warden.scan.pinning import PinStore

logger = get_logger(__name__)


class DefinitionIntegrity:
    """Refuse a call to a tool whose definition is not pinned.

    Reads the pin store's in-memory view rather than the database, so a `tools/call` never
    waits on a query to find out whether a tool is quarantined. The view is rebuilt whenever an
    upstream's listing changes.
    """

    name = "definitions"

    def __init__(self, pins: PinStore) -> None:
        self._pins = pins

    async def run(self, ctx: RequestContext) -> None:
        if ctx.tool_name is None:  # pragma: no cover - resolve runs first
            return
        reason = self._pins.quarantine_reason(ctx.tool_name)
        if reason is None:
            return
        ctx.scan_flags["quarantine_reason"] = str(reason)
        ctx.deny(
            ReasonCode.DENIED_QUARANTINED,
            f"'{ctx.tool_name}' is quarantined ({reason}); an admin must approve its "
            f"current definition before it can be called",
        )


class ArgumentDLP:
    """Refuse a call whose arguments carry a secret.

    This is where an exfiltration attempt is actually stopped: the poisoned description
    persuaded the model to read a key, the policy may have permitted the read, and this is the
    moment the key would leave.
    """

    name = "dlp"

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    async def run(self, ctx: RequestContext) -> None:
        report = scan_arguments(
            ctx.arguments,
            canaries=self._config.canaries,
            suspicious_at=self._config.definition_suspicious_score,
            malicious_at=self._config.definition_malicious_score,
        )
        if report.findings:
            # Evidence is already excerpted and masked by the scanner, so this is safe to
            # record; the raw values never appear.
            ctx.scan_flags["dlp"] = report.as_dict()
            # And mark the arguments that carried a secret, so whatever stores the arguments
            # masks them too. Their hash still covers the real values.
            ctx.redact_paths.update(finding.where for finding in report.findings if finding.where)
        if report.clean:
            return
        logger.warning(
            "argument DLP refused a call",
            extra={
                "warden": {
                    "tool": ctx.tool_name,
                    "verdict": str(report.verdict),
                    "rules": list(report.rules),
                }
            },
        )
        ctx.deny(
            ReasonCode.DENIED_DLP,
            "the arguments look like they contain a secret "
            f"({', '.join(report.rules)}); the call was not forwarded",
        )


class OutputScan:
    """Scan the result, then block it or wrap it.

    Runs after the size limit, so an oversized result is refused before anything scans it.
    """

    name = "output_scan"

    def __init__(self, scanner: OutputScanner, servers: ServersConfig) -> None:
        self._scanner = scanner
        self._servers = servers

    async def run(self, ctx: RequestContext) -> None:
        if ctx.result is None or ctx.upstream is None:
            return
        upstream = self._servers.by_name(ctx.upstream)
        if upstream is None:  # pragma: no cover - resolve guarantees this
            return
        outcome = await self._scanner.scan(
            ctx.result, action=upstream.effective_output_action, trusted=upstream.trusted
        )
        if outcome.flagged or outcome.report.classifier_score is not None:
            ctx.scan_flags["output"] = {
                **outcome.report.as_dict(),
                "action": str(outcome.action),
                "blocked": outcome.block,
                "wrapped": outcome.wrap,
            }
        if outcome.block:
            logger.warning(
                "tool output blocked as a possible injection",
                extra={
                    "warden": {
                        "tool": ctx.tool_name,
                        "upstream": ctx.upstream,
                        "rules": list(outcome.report.rules),
                        "score": outcome.report.score,
                    }
                },
            )
            ctx.result = None
            ctx.deny(
                ReasonCode.DENIED_INJECTION,
                "the tool's output was flagged as a possible prompt injection "
                f"({', '.join(outcome.report.rules)}) and was not returned",
            )
            return
        if outcome.wrap:
            ctx.result = wrap_result(ctx.result, outcome.report)


__all__ = ["ArgumentDLP", "DefinitionIntegrity", "OutputScan"]
