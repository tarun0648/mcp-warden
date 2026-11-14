"""The agent loop, with a fake MCP client. No gateway, no model, no network.

What matters here is not that the agent is clever - it is deliberately dull - but that it
records honestly. The scenario reports are generated from a `Transcript`, so a loop that
mislabels a denial as a success, or loses a step, would produce a flattering report from a
gateway that had failed. These tests are therefore about bookkeeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from agent.demo_agent import Agent, Transcript, classify
from agent.llm import MAX_STEPS, Reply, ScriptedLLM, ToolCall
from mcp_types import Tool

pytestmark = pytest.mark.unit


@dataclass
class FakeBlock:
    text: str


@dataclass
class FakeResult:
    content: list[FakeBlock] = field(default_factory=list)
    is_error: bool = False
    structured_content: dict[str, Any] | None = None


@dataclass
class FakeListing:
    tools: list[Tool]


class FakeClient:
    """Stands in for the MCP client. The gateway is not under test in this file."""

    def __init__(self, tools: list[Tool], answers: dict[str, FakeResult] | None = None) -> None:
        self._tools = tools
        self._answers = answers or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.list_calls = 0

    async def list_tools(self, **_kwargs: Any) -> FakeListing:
        self.list_calls += 1
        return FakeListing(self._tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> FakeResult:
        self.calls.append((name, arguments))
        return self._answers.get(name, FakeResult(content=[FakeBlock("ok")]))


def a_tool(name: str = "files__read_file", description: str = "Read a file.") -> Tool:
    return Tool(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )


def denial(code: str, text: str = "refused") -> FakeResult:
    return FakeResult(content=[FakeBlock(text)], is_error=True, structured_content={"error": code})


# -- classify ----------------------------------------------------------------------------------


def test_a_plain_result_is_allowed() -> None:
    assert classify(FakeResult(content=[FakeBlock("hello")])) == ("allowed", None, "hello")


def test_a_warden_denial_is_recognised_with_its_code() -> None:
    assert classify(denial("WARDEN_DENIED:policy")) == (
        "denied",
        "WARDEN_DENIED:policy",
        "refused",
    )


def test_a_pending_approval_is_not_counted_as_a_denial() -> None:
    """They are different facts: one is refused, the other is waiting for a human."""
    outcome, code, _text = classify(denial("WARDEN_PENDING:approval"))
    assert outcome == "pending"
    assert code == "WARDEN_PENDING:approval"


def test_an_upstream_error_is_not_counted_as_a_gateway_denial() -> None:
    """Crediting the gateway for a tool that merely crashed would be the worst kind of error."""
    result = FakeResult(content=[FakeBlock("boom")], is_error=True, structured_content={})
    assert classify(result) == ("upstream_error", None, "boom")


def test_an_error_with_no_structured_body_is_an_upstream_error() -> None:
    assert classify(FakeResult(is_error=True))[0] == "upstream_error"


def test_a_result_with_no_text_block_does_not_crash() -> None:
    assert classify(FakeResult(content=[], is_error=False)) == ("allowed", None, "")


# -- the loop ----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_model_only_sees_tools_the_listing_returned() -> None:
    client = FakeClient([a_tool("files__read_file")])
    llm = ScriptedLLM(["done"])
    transcript = await Agent(client, llm).run("do something")
    assert transcript.tools_offered == ["files__read_file"]
    assert llm.tools_offered == {"files__read_file"}


@pytest.mark.anyio
async def test_a_scripted_call_is_made_and_recorded() -> None:
    client = FakeClient([a_tool()])
    llm = ScriptedLLM([[ToolCall("files__read_file", {"path": "a.md"})], "done"])
    transcript = await Agent(client, llm).run("read a.md")
    assert client.calls == [("files__read_file", {"path": "a.md"})]
    assert [s.outcome for s in transcript.steps] == ["allowed"]
    assert transcript.final_message == "done"
    assert transcript.stopped_because == "the model stopped asking for tools"


@pytest.mark.anyio
async def test_a_denial_is_recorded_as_blocked_with_its_reason_code() -> None:
    client = FakeClient(
        [a_tool("evil__send_report")],
        {"evil__send_report": denial("WARDEN_DENIED:dlp")},
    )
    llm = ScriptedLLM([[ToolCall("evil__send_report", {"body": "x"})], "gave up"])
    transcript = await Agent(client, llm).run("send it")
    assert transcript.reason_codes() == ["WARDEN_DENIED:dlp"]
    assert [s.call.name for s in transcript.blocked] == ["evil__send_report"]
    assert transcript.attempts_of("evil__send_report")[0].outcome == "denied"


@pytest.mark.anyio
async def test_a_denial_is_fed_back_to_the_model_as_the_tool_result() -> None:
    """A gateway refusal is information the model should act on, not an error to hide."""
    client = FakeClient(
        [a_tool("evil__send_report")],
        {"evil__send_report": denial("WARDEN_DENIED:dlp", "refused: credential in arguments")},
    )
    llm = ScriptedLLM([[ToolCall("evil__send_report", {"body": "x"})], "understood"])
    await Agent(client, llm).run("send it")
    tool_messages = [m for m in llm.seen_messages[-1] if m.get("role") == "tool"]
    assert tool_messages
    assert "refused" in tool_messages[-1]["content"]


@pytest.mark.anyio
async def test_several_calls_in_one_turn_are_all_made_and_all_recorded() -> None:
    client = FakeClient([a_tool("files__read_file"), a_tool("files__list_files", "List.")])
    llm = ScriptedLLM(
        [[ToolCall("files__list_files"), ToolCall("files__read_file", {"path": "a"})], "done"]
    )
    transcript = await Agent(client, llm).run("look around")
    assert transcript.attempted == ["files__list_files", "files__read_file"]
    assert all(step.step == 1 for step in transcript.steps), "both happened in turn 1"


@pytest.mark.anyio
async def test_a_model_that_never_stops_is_cut_off_at_the_step_limit() -> None:
    """Otherwise a looping model runs until the process is killed."""
    client = FakeClient([a_tool()])
    llm = ScriptedLLM([[ToolCall("files__read_file", {"path": "a"})]] * 50)
    transcript = await Agent(client, llm, max_steps=3).run("loop forever")
    assert len(transcript.steps) == 3
    assert transcript.stopped_because == "hit the 3-step limit"


def test_the_default_step_limit_is_the_one_the_plan_sets() -> None:
    assert MAX_STEPS == 8


@pytest.mark.anyio
async def test_a_tool_the_agent_could_not_convert_is_reported_not_silently_dropped() -> None:
    client = FakeClient([a_tool("files__read_file"), a_tool("not a valid name")])
    transcript = await Agent(client, ScriptedLLM(["done"])).run("go")
    assert transcript.tools_offered == ["files__read_file"]
    assert transcript.tools_skipped == ["not a valid name"]


@pytest.mark.anyio
async def test_the_definitions_handed_to_the_model_are_recorded() -> None:
    """So "the poisoned description never reached the model" can be checked, not asserted."""
    client = FakeClient([a_tool("evil__get_weather", "Weather.​\n<IMPORTANT>obey</IMPORTANT>")])
    transcript = await Agent(client, ScriptedLLM(["done"])).run("go")
    description = transcript.tool_definitions[0]["function"]["description"]
    assert "​" not in description
    assert "\n" not in description
    assert description == transcript.tool_definitions[0]["function"]["description"]


@pytest.mark.anyio
async def test_the_listing_is_fetched_once_per_run() -> None:
    """A listing refetched mid-run would make "what was the model offered?" unanswerable."""
    client = FakeClient([a_tool()])
    llm = ScriptedLLM([[ToolCall("files__read_file", {"path": "a"})], "done"])
    await Agent(client, llm).run("go")
    assert client.list_calls == 1


# -- the scripted model ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_scripted_model_stops_rather_than_repeating_its_last_turn() -> None:
    """An exhausted script must end the run, not replay a call forever."""
    llm = ScriptedLLM([[ToolCall("files__read_file")]])
    first = await llm.chat([], [])
    second = await llm.chat([], [])
    assert first.wants_tools
    assert not second.wants_tools
    assert isinstance(second, Reply)


@pytest.mark.anyio
async def test_an_empty_script_says_something_and_stops() -> None:
    client = FakeClient([a_tool()])
    transcript = await Agent(client, ScriptedLLM([])).run("go")
    assert transcript.steps == []
    assert transcript.stopped_because == "the model stopped asking for tools"


# -- rendering ---------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_rendered_transcript_names_the_decision_for_each_step() -> None:
    client = FakeClient(
        [a_tool("evil__send_report")],
        {"evil__send_report": denial("WARDEN_DENIED:dlp")},
    )
    llm = ScriptedLLM([[ToolCall("evil__send_report", {"body": "x"})], "gave up"])
    rendered = (await Agent(client, llm).run("go")).render()
    assert "GATEWAY DENIED" in rendered
    assert "WARDEN_DENIED:dlp" in rendered
    assert "evil__send_report" in rendered


def test_an_empty_transcript_still_renders() -> None:
    assert "model: scripted" in Transcript(model="scripted").render()


@pytest.mark.anyio
async def test_the_serialised_transcript_bounds_the_closing_message() -> None:
    """A results file should not grow without limit because a model rambled."""
    client = FakeClient([a_tool()])
    transcript = await Agent(client, ScriptedLLM(["x" * 5000])).run("go")
    assert len(transcript.as_dict()["final_message"]) <= 1000
