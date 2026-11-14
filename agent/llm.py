"""The model behind the agent, behind an interface.

Two implementations:

* `OllamaLLM` talks to a local Ollama. No paid API is involved anywhere in this project.
* `ScriptedLLM` replays a fixed sequence of tool calls.

The scripted one is not a convenience, it is what makes the scenarios *tests*. A 7B model
takes the bait inconsistently - sometimes it follows the injected instruction, sometimes it
notices and refuses - so a scenario driven by a real model cannot assert anything about the
gateway. The scripted model always takes the bait, which turns "did the gateway block it?" into
a question with an answer. The real model is then run separately to show that the whole thing
works end to end with an actual LLM in the loop.

This is the point CLAUDE.md makes about judging the gateway and not the model.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from warden.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MODEL: Final = "qwen2.5:7b"
#: Keeps a stuck model from running forever. The plan's limit.
MAX_STEPS: Final = 8


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool the model wants called."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.name}({json.dumps(self.arguments, default=str)[:160]})"


@dataclass(frozen=True, slots=True)
class Reply:
    """What the model said this turn."""

    content: str = ""
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class LLM(Protocol):
    """Anything the agent can talk to."""

    name: str

    async def chat(
        self, messages: Sequence[dict[str, Any]], tools: Sequence[dict[str, Any]]
    ) -> Reply: ...


class ScriptedLLM:
    """Replays a plan of tool calls, then a closing message.

    Each entry is either a list of `ToolCall`s for that turn, or a string to say and stop. The
    script is consumed one turn at a time, so a scenario can describe a model that tries one
    thing, sees the gateway's refusal, and tries another.
    """

    def __init__(self, plan: Sequence[Sequence[ToolCall] | str], *, name: str = "scripted"):
        self.name = name
        self._plan = list(plan)
        self._turn = 0
        #: Every `(messages, tools)` the agent sent, so a test can assert what the model saw -
        #: which is how the "poisoned tool never reaches the model" scenario is checked.
        self.seen_tools: list[list[str]] = []
        self.seen_messages: list[list[dict[str, Any]]] = []

    async def chat(
        self, messages: Sequence[dict[str, Any]], tools: Sequence[dict[str, Any]]
    ) -> Reply:
        self.seen_tools.append([t["function"]["name"] for t in tools])
        self.seen_messages.append([dict(m) for m in messages])
        if self._turn >= len(self._plan):
            return Reply(content="(scripted model has nothing further to do)")
        entry = self._plan[self._turn]
        self._turn += 1
        if isinstance(entry, str):
            return Reply(content=entry)
        return Reply(content="", tool_calls=tuple(entry))

    @property
    def tools_offered(self) -> set[str]:
        """Every tool name the agent ever put in front of the model."""
        return {name for names in self.seen_tools for name in names}


class OllamaLLM:
    """A local Ollama model."""

    def __init__(self, model: str | None = None, *, host: str | None = None) -> None:
        self.model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
        self.name = f"ollama:{self.model}"
        self._host = host or os.environ.get("OLLAMA_HOST")
        self._client: Any | None = None

    def _ensure(self) -> Any:
        if self._client is None:
            import ollama

            self._client = (
                ollama.AsyncClient(host=self._host) if self._host else ollama.AsyncClient()
            )
        return self._client

    async def chat(
        self, messages: Sequence[dict[str, Any]], tools: Sequence[dict[str, Any]]
    ) -> Reply:
        client = self._ensure()
        response = await client.chat(
            model=self.model,
            messages=list(messages),
            tools=list(tools) or None,
            # Deterministic as the model can be, so repeated runs are comparable.
            options={"temperature": 0.0, "num_ctx": 8192},
        )
        message = response.get("message", {}) if isinstance(response, dict) else response.message
        content = _text_of(message)
        calls = tuple(_tool_calls_of(message))
        return Reply(content=content, tool_calls=calls)

    async def available(self) -> tuple[bool, str]:
        """Whether this model can actually be used, and why not if it cannot."""
        try:
            client = self._ensure()
        except ImportError:
            return False, "the 'ollama' package is not installed (uv sync --extra agent)"
        try:
            listing = await client.list()
        except Exception as exc:
            return False, f"cannot reach Ollama: {type(exc).__name__}: {exc}"
        names = (
            {
                str(model.get("model") or model.get("name"))
                for model in (listing.get("models") or [])
            }
            if isinstance(listing, dict)
            else {str(getattr(model, "model", "")) for model in getattr(listing, "models", [])}
        )
        if not any(name.startswith(self.model.split(":")[0]) for name in names):
            return False, f"model {self.model} is not pulled (ollama pull {self.model})"
        return True, "ready"


def _text_of(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("content") or "")
    return str(getattr(message, "content", "") or "")


def _tool_calls_of(message: Any) -> list[ToolCall]:
    raw = (
        message.get("tool_calls")
        if isinstance(message, dict)
        else getattr(message, "tool_calls", None)
    )
    calls: list[ToolCall] = []
    for entry in raw or []:
        function = (
            entry.get("function") if isinstance(entry, dict) else getattr(entry, "function", None)
        )
        if function is None:
            continue
        name = (
            function.get("name") if isinstance(function, dict) else getattr(function, "name", None)
        )
        arguments = (
            function.get("arguments")
            if isinstance(function, dict)
            else getattr(function, "arguments", None)
        )
        if isinstance(arguments, str):
            # Some models return the arguments as a JSON string rather than an object.
            try:
                arguments = json.loads(arguments or "{}")
            except json.JSONDecodeError:
                logger.warning(
                    "model returned unparseable tool arguments",
                    extra={"warden": {"tool": name}},
                )
                arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        if name:
            calls.append(ToolCall(name=str(name), arguments=dict(arguments)))
    return calls


__all__ = [
    "DEFAULT_MODEL",
    "LLM",
    "MAX_STEPS",
    "OllamaLLM",
    "Reply",
    "ScriptedLLM",
    "ToolCall",
]
