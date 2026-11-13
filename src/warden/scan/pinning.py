"""Pinning tool definitions, and quarantining the ones that change or look hostile.

The lifecycle of one upstream tool:

1. **First sighting.** The definition is scanned.
   * A *trusted* server's clean tool is pinned automatically. Trust is declared in
     `servers.yaml` and means "I accept this server's definitions without reading each one".
   * An *untrusted* server's tool starts `quarantined`, whatever the scan says, until an
     operator approves it. That is what `trusted: false` buys.
   * A tool whose scan is `malicious` is quarantined no matter who serves it. A trusted server
     can be compromised, and that is precisely the case where auto-pinning must not apply.
2. **Later sightings.** The hash is compared with the pin.
   * Same hash: nothing happens.
   * Different hash: **quarantined**, loudly. This is the rug pull - a definition that was
     benign when it was approved and is not any more. The previous definition is kept so
     `warden tools diff` can show exactly what changed.
3. **Approval.** An operator reviews the diff and runs `warden tools approve <tool>`, which
   pins the new hash and records who accepted it.

A quarantined tool is hidden from `tools/list` and refused on call with
`WARDEN_DENIED:quarantined`. Hiding as well as refusing matters: a model that can see a tool
will keep trying it, and the description is the attack.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp_types import Tool
from sqlalchemy import select

from warden.db.base import utcnow
from warden.db.engine import Database
from warden.db.models import ToolPin
from warden.logging import get_logger
from warden.scan.definitions import DefinitionScan, DefinitionScanner, definition_hash
from warden.scan.findings import Verdict

logger = get_logger(__name__)


class PinStatus(StrEnum):
    PINNED = "pinned"
    QUARANTINED = "quarantined"


class QuarantineReason(StrEnum):
    """Why a tool is not usable. Reported to operators and counted in metrics."""

    UNTRUSTED_FIRST_SIGHT = "untrusted_server_awaiting_approval"
    MALICIOUS_DEFINITION = "definition_scan_malicious"
    DEFINITION_CHANGED = "definition_changed_since_approval"


@dataclass(frozen=True, slots=True)
class PinOutcome:
    """What reconciling one definition against its pin decided."""

    server: str
    tool: str
    status: PinStatus
    reason: QuarantineReason | None
    scan: DefinitionScan
    #: True when this sighting changed the stored status.
    changed: bool = False
    previous_sha256: str | None = None

    @property
    def quarantined(self) -> bool:
        return self.status is PinStatus.QUARANTINED

    @property
    def name(self) -> str:
        return f"{self.server}__{self.tool}"


class PinStore:
    """Reads and writes `tool_pins`, and decides what each sighting means."""

    def __init__(self, database: Database, scanner: DefinitionScanner) -> None:
        self._db = database
        self._scanner = scanner
        #: The in-memory view the request path reads, so a `tools/call` never waits on the
        #: database to find out whether a tool is quarantined. Rebuilt on every reconcile.
        self._quarantined: dict[str, QuarantineReason] = {}

    # -- the fast path the pipeline uses --------------------------------------------------

    def is_quarantined(self, namespaced_name: str) -> bool:
        return namespaced_name in self._quarantined

    def quarantine_reason(self, namespaced_name: str) -> QuarantineReason | None:
        return self._quarantined.get(namespaced_name)

    @property
    def quarantined_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._quarantined))

    def allowed_names(self, names: Iterable[str]) -> list[str]:
        """Filter a tool list down to the ones that are not quarantined."""
        return [name for name in names if name not in self._quarantined]

    # -- reconciling ---------------------------------------------------------------------

    async def reconcile(
        self,
        tools_by_upstream: Mapping[str, Sequence[Tool]],
        *,
        trusted_servers: Iterable[str],
    ) -> list[PinOutcome]:
        """Scan every current definition, update the pins, and refresh the fast path.

        Called at startup and whenever an upstream's listing changes, which is what makes a rug
        pull visible between calls rather than only on restart.
        """
        trusted = set(trusted_servers)
        all_servers = set(tools_by_upstream)
        all_names = [
            f"{server}__{tool.name}"
            for server, tools in tools_by_upstream.items()
            for tool in tools
        ]
        outcomes: list[PinOutcome] = []

        for server, tools in sorted(tools_by_upstream.items()):
            for tool in tools:
                scan = await self._scanner.scan(
                    tool,
                    server=server,
                    other_servers=all_servers - {server},
                    other_tools=[name for name in all_names if not name.startswith(f"{server}__")],
                )
                outcomes.append(
                    await self._reconcile_one(tool, scan=scan, trusted=server in trusted)
                )

        self._quarantined = {
            outcome.name: outcome.reason
            for outcome in outcomes
            if outcome.quarantined and outcome.reason is not None
        }
        return outcomes

    async def _reconcile_one(
        self, tool: Tool, *, scan: DefinitionScan, trusted: bool
    ) -> PinOutcome:
        digest = scan.sha256
        async with self._db.session() as session:
            existing = (
                await session.execute(
                    select(ToolPin).where(ToolPin.server == scan.server, ToolPin.tool == scan.tool)
                )
            ).scalar_one_or_none()

            definition = tool.model_dump(mode="json", by_alias=True)
            status, reason = self._decide(
                existing=existing, digest=digest, scan=scan, trusted=trusted
            )
            previous = existing.sha256 if existing is not None else None
            changed = existing is None or existing.status != str(status) or previous != digest

            if existing is None:
                session.add(
                    ToolPin(
                        server=scan.server,
                        tool=scan.tool,
                        sha256=digest,
                        status=str(status),
                        scan=scan.as_dict(),
                        definition=definition,
                        reason=str(reason) if reason else None,
                    )
                )
            elif changed:
                # The old definition is kept only while the hash is unchanged; once it differs
                # the previous one is what `diff` needs, so it is preserved alongside.
                if previous != digest:
                    existing.scan = {
                        **scan.as_dict(),
                        "previous_sha256": previous,
                        "previous_definition": existing.definition,
                    }
                else:
                    existing.scan = scan.as_dict()
                existing.sha256 = digest
                existing.status = str(status)
                existing.reason = str(reason) if reason else None
                existing.definition = definition
                existing.updated_at = utcnow()

        if changed and status is PinStatus.QUARANTINED:
            logger.error(
                "TOOL QUARANTINED",
                extra={
                    "warden": {
                        "tool": f"{scan.server}__{scan.tool}",
                        "reason": str(reason),
                        "verdict": str(scan.report.verdict),
                        "score": scan.report.score,
                        "rules": list(scan.report.rules),
                        "previous_sha256": previous,
                        "sha256": digest,
                    }
                },
            )
        elif changed and status is PinStatus.PINNED:
            logger.info(
                "tool pinned",
                extra={"warden": {"tool": f"{scan.server}__{scan.tool}", "sha256": digest}},
            )

        return PinOutcome(
            server=scan.server,
            tool=scan.tool,
            status=status,
            reason=reason,
            scan=scan,
            changed=changed,
            previous_sha256=previous,
        )

    @staticmethod
    def _decide(
        *, existing: ToolPin | None, digest: str, scan: DefinitionScan, trusted: bool
    ) -> tuple[PinStatus, QuarantineReason | None]:
        """The whole pinning policy, in one readable place."""
        # A malicious definition is quarantined whoever serves it. A trusted server can be
        # compromised, and that is exactly when auto-pinning must not apply.
        if scan.report.verdict is Verdict.MALICIOUS:
            return PinStatus.QUARANTINED, QuarantineReason.MALICIOUS_DEFINITION

        if existing is None:
            if trusted and scan.report.verdict is Verdict.CLEAN:
                return PinStatus.PINNED, None
            return PinStatus.QUARANTINED, QuarantineReason.UNTRUSTED_FIRST_SIGHT

        if existing.sha256 != digest:
            return PinStatus.QUARANTINED, QuarantineReason.DEFINITION_CHANGED

        # Unchanged: whatever an operator decided last time still stands.
        if existing.status == str(PinStatus.PINNED):
            return PinStatus.PINNED, None
        return PinStatus.QUARANTINED, (
            QuarantineReason(existing.reason)
            if existing.reason in {str(r) for r in QuarantineReason}
            else QuarantineReason.UNTRUSTED_FIRST_SIGHT
        )

    # -- operator actions ----------------------------------------------------------------

    async def list_pins(self, *, status: str | None = None) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            statement = select(ToolPin).order_by(ToolPin.server, ToolPin.tool)
            if status:
                statement = statement.where(ToolPin.status == status)
            return [row.as_dict() for row in (await session.execute(statement)).scalars()]

    async def get_pin(self, server: str, tool: str) -> dict[str, Any] | None:
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(ToolPin).where(ToolPin.server == server, ToolPin.tool == tool)
                )
            ).scalar_one_or_none()
            return row.as_dict() if row is not None else None

    async def definitions_for_diff(
        self, server: str, tool: str
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """The previously pinned definition and the current one, for `warden tools diff`.

        Kept off `ToolPin.as_dict()` on purpose: a definition is attacker-controlled text, and
        the pins *listing* has no reason to carry every poisoned description. Only the diff
        endpoint asks for it, and it renders both sides through `excerpt`.
        """
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(ToolPin).where(ToolPin.server == server, ToolPin.tool == tool)
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            previous = dict((row.scan or {}).get("previous_definition") or {})
            return previous, dict(row.definition or {})

    async def approve(self, server: str, tool: str, *, approved_by: str) -> bool:
        """Pin the current definition. Returns False if there is nothing to approve."""
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(ToolPin).where(ToolPin.server == server, ToolPin.tool == tool)
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            row.status = str(PinStatus.PINNED)
            row.reason = None
            row.approved_by = approved_by
            row.approved_at = utcnow()
            row.updated_at = utcnow()
        self._quarantined.pop(f"{server}__{tool}", None)
        logger.warning(
            "tool pin approved",
            extra={"warden": {"tool": f"{server}__{tool}", "approved_by": approved_by}},
        )
        return True

    async def quarantine(self, server: str, tool: str, *, by: str, reason: str) -> bool:
        """Quarantine a tool by hand, for an operator who has seen something we have not."""
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(ToolPin).where(ToolPin.server == server, ToolPin.tool == tool)
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            row.status = str(PinStatus.QUARANTINED)
            row.reason = reason
            row.approved_by = by
            row.approved_at = None
            row.updated_at = utcnow()
        self._quarantined[f"{server}__{tool}"] = QuarantineReason.MALICIOUS_DEFINITION
        logger.warning(
            "tool quarantined by an operator",
            extra={"warden": {"tool": f"{server}__{tool}", "by": by, "reason": reason}},
        )
        return True

    async def load_quarantine_view(self) -> None:
        """Rebuild the fast path from the database, for a process that has just started."""
        rows = await self.list_pins(status=str(PinStatus.QUARANTINED))
        self._quarantined = {
            row["name"]: (
                QuarantineReason(row["reason"])
                if row["reason"] in {str(r) for r in QuarantineReason}
                else QuarantineReason.UNTRUSTED_FIRST_SIGHT
            )
            for row in rows
        }


__all__ = [
    "PinOutcome",
    "PinStatus",
    "PinStore",
    "QuarantineReason",
    "definition_hash",
]
