"""Fill omitted arguments from the pinned schema, so the gateway checks what it forwards.

The problem this solves was found by the soak test. `files__list_files` declares `path`
optional with a default of `"."`. The policy constrains `path`. A constraint on an *absent*
argument fails closed - correctly, because the gateway cannot know what an upstream does with a
missing value - so a schema-conforming `list_files {}` was refused.

Treating "absent" as "fine" would be the wrong fix: it would let an upstream's default bypass a
constraint the operator wrote. Instead the gateway applies the default itself, *before* policy,
and the filled value is what every later stage sees and what is forwarded. The value that is
checked and the value that runs are then the same value, rather than the gateway checking
nothing and the upstream silently substituting something.

Where the default comes from matters. This stage runs after `DefinitionIntegrity`, so the tool
is pinned and not quarantined, and it reads the registry's definition - which equals the pinned
one, because on a listing change pins are reconciled *before* the registry is replaced (see
`on_tools_changed` in `warden.main`). A rug pull that changed only a default changes the
definition hash, quarantines the tool, and is refused before its new default could be read.

Two deliberate limits:

* **`null` defaults are not filled.** Pydantic writes `"default": null` for every
  `Optional[...] = None` parameter. Sending an explicit `null` would make a constraint marked
  `optional: true` - which tolerates absence - see a value of the wrong type and deny, turning
  this fix into a new false positive.
* **Top level only.** Constraints name top-level arguments; filling nested defaults would change
  payloads no constraint looks at.

Which arguments were filled is recorded in `scan_flags`, so the audit row says what the caller
sent and what the gateway added.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from warden.pipeline import RequestContext
from warden.proxy.registry import ToolRegistry

#: The key under which filled argument names are recorded in `RequestContext.scan_flags`.
FLAG = "defaults_filled"


@dataclass(frozen=True, slots=True)
class Filled:
    """The arguments after filling, and the names that were added."""

    arguments: dict[str, Any]
    names: tuple[str, ...] = field(default_factory=tuple)


def fill_defaults(schema: Any, arguments: Mapping[str, Any]) -> Filled:
    """Add each top-level property's non-null default the caller left out.

    Never overwrites a value the caller sent - including an explicit `null` - and never raises:
    a malformed schema fills nothing and policy decides as it would have.
    """
    result = dict(arguments)
    if not isinstance(schema, Mapping):
        return Filled(result)
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return Filled(result)
    added: list[str] = []
    for name, prop in properties.items():
        if not isinstance(name, str) or name in result or not isinstance(prop, Mapping):
            continue
        if "default" not in prop or prop["default"] is None:
            continue
        # A copy, so a mutable default in the registry's definition can never be changed
        # through one request's arguments and leak into the next.
        result[name] = copy.deepcopy(prop["default"])
        added.append(name)
    return Filled(result, tuple(sorted(added)))


class ApplySchemaDefaults:
    """Pipeline stage: fill omitted arguments from the pinned definition. Never denies."""

    name = "defaults"

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    async def run(self, ctx: RequestContext) -> None:
        if ctx.tool_name is None:  # pragma: no cover - resolve runs first
            return
        registered = self._registry.get(ctx.tool_name)
        if registered is None:  # pragma: no cover - resolve has already denied it
            return
        filled = fill_defaults(registered.definition.input_schema, ctx.arguments)
        if filled.names:
            ctx.arguments = filled.arguments
            ctx.scan_flags[FLAG] = list(filled.names)


__all__ = ["FLAG", "ApplySchemaDefaults", "Filled", "fill_defaults"]
