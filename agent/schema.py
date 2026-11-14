"""Turning MCP tool definitions into the function format Ollama expects.

Ollama takes OpenAI-shaped tools: `{"type": "function", "function": {name, description,
parameters}}`, where `parameters` is a JSON Schema object. MCP's `inputSchema` is already JSON
Schema, so most of this is reshaping rather than translating - but three things do need care,
and each has tests:

* **The description is untrusted.** It comes from the upstream server and goes straight into the
  model's context, which is exactly the tool-poisoning channel. The gateway has already
  quarantined anything that scanned malicious, so what arrives here has been reviewed; the
  agent still truncates it and strips invisible characters, because an agent is a client like
  any other and should not assume its gateway is perfect.
* **Names must match what Ollama accepts.** The namespaced `server__tool` form is fine, but a
  name is still validated rather than assumed.
* **Schema keywords Ollama does not understand** are dropped rather than passed through, since
  a model that receives a keyword it cannot interpret tends to ignore the whole schema.
"""

from __future__ import annotations

import re
from typing import Any, Final

#: What Ollama (and the OpenAI function format) accepts as a function name.
NAME_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_DESCRIPTION_CHARS: Final = 1024

#: JSON Schema keywords worth forwarding. Everything else is dropped: `$ref`, `$defs`,
#: `allOf`, `oneOf`, `not`, `if`/`then` and friends confuse a small model more than they help
#: it, and an unresolved `$ref` is worse than an absent constraint.
KEPT_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "description",
        "title",
        "enum",
        "const",
        "default",
        "properties",
        "required",
        "items",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "additionalProperties",
        "format",
    }
)

#: Characters that are invisible or change reading order. Stripped from any text that reaches
#: the model, for the same reason the gateway's scanner flags them.
_INVISIBLE: Final = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")


class UnusableTool(ValueError):
    """The tool cannot be offered to the model."""


def clean_text(text: str | None, *, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    """Make upstream text safe to put in a prompt: visible, single-paragraph, bounded."""
    if not text:
        return ""
    stripped = _INVISIBLE.sub("", text)
    collapsed = " ".join(stripped.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def convert_schema(schema: Any) -> dict[str, Any]:
    """Recursively keep the JSON Schema keywords a small model can actually use."""
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}}
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key not in KEPT_KEYWORDS:
            continue
        if key == "properties" and isinstance(value, dict):
            out[key] = {name: convert_schema(sub) for name, sub in value.items()}
        elif key == "items":
            out[key] = convert_schema(value) if isinstance(value, dict) else value
        elif key == "additionalProperties" and isinstance(value, dict):
            out[key] = convert_schema(value)
        elif key in ("description", "title") and isinstance(value, str):
            out[key] = clean_text(value, limit=256)
        else:
            out[key] = value
    # A parameters object with no type confuses the function-calling path, so it is supplied.
    if "type" not in out and ("properties" in out or not out):
        out["type"] = "object"
    if out.get("type") == "object" and "properties" not in out:
        out["properties"] = {}
    return out


def to_ollama_tool(tool: Any) -> dict[str, Any]:
    """One MCP `Tool` as an Ollama function definition.

    Raises `UnusableTool` rather than silently offering the model something malformed: a tool
    the model cannot call is better left out of the list than included and broken.
    """
    name = getattr(tool, "name", "")
    if not NAME_RE.match(name):
        raise UnusableTool(f"'{name}' is not a usable function name")
    description = clean_text(getattr(tool, "description", None))
    if not description:
        description = f"Call the {name} tool."
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": convert_schema(getattr(tool, "input_schema", None)),
        },
    }


def to_ollama_tools(tools: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Convert a whole listing. Returns (definitions, names that could not be converted)."""
    converted: list[dict[str, Any]] = []
    skipped: list[str] = []
    for tool in tools:
        try:
            converted.append(to_ollama_tool(tool))
        except UnusableTool:
            skipped.append(str(getattr(tool, "name", "?")))
    return converted, skipped


__all__ = [
    "KEPT_KEYWORDS",
    "MAX_DESCRIPTION_CHARS",
    "NAME_RE",
    "UnusableTool",
    "clean_text",
    "convert_schema",
    "to_ollama_tool",
    "to_ollama_tools",
]
