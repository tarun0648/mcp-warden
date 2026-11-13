"""The policy engine: deny by default, deny beats allow.

Evaluation order, for a principal whose roles are R and a tool T with arguments A:

1. Collect every rule in every role of R whose tool patterns match T.
2. If any matching rule has `effect: deny`, the call is denied, naming that rule.
3. Otherwise, the first matching allow rule whose argument constraints all pass permits the
   call, naming that rule.
4. Otherwise the call is denied. No rule means no permission.

Step 4 is the whole design: an unknown role, an unknown tool, an empty policy file and a typo in
a tool name all end in the same place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from warden.config import PoliciesConfig, PolicyRule, Risk, ServersConfig, split_namespaced
from warden.logging import get_logger
from warden.pipeline import Principal
from warden.policy.constraints import ConstraintFailure, check_constraints
from warden.policy.matching import matches_any

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The outcome of evaluating one call."""

    allowed: bool
    reason: str
    rule_id: str | None = None
    #: The risk level to apply, after any rule override.
    risk: Risk = Risk.READ
    requires_approval: bool = False
    failures: tuple[ConstraintFailure, ...] = field(default_factory=tuple)

    @property
    def denied(self) -> bool:
        return not self.allowed


class PolicyEngine:
    """Evaluates calls, and decides what a caller may see in `tools/list`."""

    def __init__(self, policies: PoliciesConfig, servers: ServersConfig) -> None:
        self._policies = policies
        self._servers = servers

    # -- risk ----------------------------------------------------------------------------

    def risk_for(self, tool_name: str) -> Risk:
        """The tool's risk level: the policy file's override, else the upstream's default."""
        override = self._policies.tool_risk.get(tool_name)
        if override is not None:
            return override
        parts = split_namespaced(tool_name)
        if parts is None:
            return Risk.DESTRUCTIVE  # an unnamespaced name should never reach here
        server, tool = parts
        upstream = self._servers.by_name(server)
        return upstream.risk_for(tool) if upstream is not None else Risk.DESTRUCTIVE

    # -- rule collection -----------------------------------------------------------------

    def _rules_for(self, principal: Principal, tool_name: str) -> list[PolicyRule]:
        """Every rule of the principal's roles that matches this tool, in role order."""
        collected: list[PolicyRule] = []
        for role in principal.roles:
            role_policy = self._policies.roles.get(role)
            if role_policy is None:
                continue
            collected.extend(
                rule for rule in role_policy.rules if matches_any(rule.tools, tool_name)
            )
        return collected

    # -- evaluation ----------------------------------------------------------------------

    def evaluate(
        self, principal: Principal | None, tool_name: str, arguments: dict[str, Any]
    ) -> PolicyDecision:
        """Decide whether this principal may make this call with these arguments."""
        risk = self.risk_for(tool_name)
        if principal is None:
            return PolicyDecision(False, "the caller is not authenticated", risk=risk)

        unknown_roles = [role for role in principal.roles if role not in self._policies.roles]
        if unknown_roles and len(unknown_roles) == len(principal.roles):
            return PolicyDecision(
                False,
                f"no policy defines role(s) {', '.join(sorted(unknown_roles))}",
                risk=risk,
            )

        candidates = self._rules_for(principal, tool_name)
        if not candidates:
            return PolicyDecision(False, f"no rule allows '{tool_name}' for this caller", risk=risk)

        # Deny wins, whatever the arguments are and whatever order the rules are in.
        for rule in candidates:
            if rule.effect == "deny":
                return PolicyDecision(
                    False,
                    rule.description or f"rule '{rule.id}' denies '{tool_name}'",
                    rule_id=rule.id,
                    risk=rule.risk or risk,
                )

        last_failures: tuple[ConstraintFailure, ...] = ()
        last_rule: str | None = None
        for rule in candidates:
            failures = tuple(check_constraints(rule.constraints, arguments))
            if failures:
                last_failures, last_rule = failures, rule.id
                continue
            effective_risk = rule.risk or risk
            return PolicyDecision(
                True,
                f"allowed by rule '{rule.id}'",
                rule_id=rule.id,
                risk=effective_risk,
                requires_approval=self._needs_approval(rule, effective_risk),
            )

        return PolicyDecision(
            False,
            "the arguments do not satisfy the policy: "
            + "; ".join(str(failure) for failure in last_failures),
            rule_id=last_rule,
            risk=risk,
            failures=last_failures,
        )

    @staticmethod
    def _needs_approval(rule: PolicyRule, risk: Risk) -> bool:
        """Destructive tools need a human unless a rule explicitly waives it."""
        if rule.require_approval is not None:
            return rule.require_approval
        return risk is Risk.DESTRUCTIVE

    # -- listing -------------------------------------------------------------------------

    def visible_tools(self, principal: Principal | None, tool_names: list[str]) -> list[str]:
        """The tools this caller may see in `tools/list`.

        Argument constraints are ignored here: a tool the caller could call with *some*
        arguments is listed. A tool whose only matching rule is a deny is not listed at all - a
        reader must not even learn that `files__delete_file` exists.
        """
        if principal is None:
            return []
        visible: list[str] = []
        for name in tool_names:
            candidates = self._rules_for(principal, name)
            if not candidates:
                continue
            if any(rule.effect == "deny" for rule in candidates):
                continue
            visible.append(name)
        return visible

    def describe(self) -> dict[str, Any]:
        """A summary for `warden check-config` and the admin API."""
        return {
            "roles": {
                role: [
                    {"id": rule.id, "effect": rule.effect, "tools": list(rule.tools)}
                    for rule in policy.rules
                ]
                for role, policy in self._policies.roles.items()
            },
            "tool_risk": {name: str(risk) for name, risk in self._policies.tool_risk.items()},
        }


__all__ = ["PolicyDecision", "PolicyEngine"]
