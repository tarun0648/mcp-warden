"""A hot-reloadable holder for the policy engine.

The gateway reads `config/policies.yaml` at startup and can reload it without a restart. A
reload that fails validation is *rejected*: the previously loaded policy stays in force and the
failure is logged loudly. Falling back to an empty policy would deny everything (an outage);
falling back to a permissive default would be worse.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from warden.config import PoliciesConfig, ServersConfig, load_policies_config
from warden.errors import ConfigError
from warden.logging import get_logger
from warden.policy.engine import PolicyEngine

logger = get_logger(__name__)


class PolicyStore:
    """Holds the current engine and swaps it atomically on a successful reload."""

    def __init__(self, path: Path | str, servers: ServersConfig) -> None:
        self.path = Path(path)
        self._servers = servers
        self._policies: PoliciesConfig = load_policies_config(self.path)
        self._engine = PolicyEngine(self._policies, self._servers)
        self.reload_count = 0
        self.last_error: str | None = None

    @classmethod
    def from_config(
        cls, path: Path | str, servers: ServersConfig, policies: PoliciesConfig | None = None
    ) -> PolicyStore:
        """Build a store, optionally from an in-memory policy (tests and the red-team runner)."""
        if policies is None:
            return cls(path, servers)
        store = cls.__new__(cls)
        store.path = Path(path)
        store._servers = servers
        store._policies = policies
        store._engine = PolicyEngine(policies, servers)
        store.reload_count = 0
        store.last_error = None
        return store

    @property
    def engine(self) -> PolicyEngine:
        """The engine in force right now. Read it per request; never cache it across a reload."""
        return self._engine

    @property
    def policies(self) -> PoliciesConfig:
        return self._policies

    def reload(self) -> tuple[bool, str]:
        """Re-read the policy file. Returns (changed, message); never raises.

        On failure the old engine is untouched, so a broken edit cannot open the gateway up or
        take it down.
        """
        try:
            fresh = load_policies_config(self.path)
        except ConfigError as exc:
            self.last_error = str(exc)
            logger.error(
                "policy reload REJECTED; the previous policy is still in force",
                extra={"warden": {"path": str(self.path), "error": str(exc)}},
            )
            return False, f"rejected: {exc}"
        if fresh == self._policies:
            logger.info("policy reload: no change", extra={"warden": {"path": str(self.path)}})
            return False, "no change"
        self._policies = fresh
        self._engine = PolicyEngine(fresh, self._servers)
        self.reload_count += 1
        self.last_error = None
        logger.warning(
            "policy reloaded",
            extra={
                "warden": {
                    "path": str(self.path),
                    "roles": sorted(fresh.roles),
                    "reload_count": self.reload_count,
                }
            },
        )
        return True, "reloaded"

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "roles": sorted(self._policies.roles),
            "rule_count": sum(len(policy.rules) for policy in self._policies.roles.values()),
            "reload_count": self.reload_count,
            "last_error": self.last_error,
        }


__all__ = ["PolicyStore"]
