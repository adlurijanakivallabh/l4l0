"""The autonomous think→act→observe loop."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.logging import get_logger
from ..core.model_router import CompletionRequest, ModelRouter
from ..observability import Tracer, get_tracer
from .monitor import LoopMonitor
from .tools import ToolRegistry, parse_tool_call

_log = get_logger("lalo.agent")

_PROTOCOL = (
    "Act ONE STEP AT A TIME. Emit EXACTLY ONE JSON object and then STOP — you will "
    "be given that tool's result before you act again. Do NOT plan or emit multiple "
    "steps at once, and do NOT call finish until you have seen real tool results.\n"
    '  {"tool": "<name>", "args": {...}}\n'
    "When the objective is genuinely met, and only then: "
    '{"tool": "finish", "args": {"summary": "..."}}\n'
    "Emit only the single JSON object, nothing else."
)


@dataclass
class AgentConfig:
    role: str = "reasoning"
    max_steps: int = 25
    max_observation_chars: int = 4000


@dataclass
class AgentResult:
    stop_reason: str
    steps: int
    transcript: list[dict[str, object]] = field(default_factory=list)
    summary: str = ""


class AgentLoop:
    def __init__(
        self,
        router: ModelRouter,
        registry: ToolRegistry,
        *,
        system_prompt: str,
        config: AgentConfig | None = None,
        tracer: Tracer | None = None,
        monitor: LoopMonitor | None = None,
    ) -> None:
        self.router = router
        self.registry = registry
        self.system_prompt = system_prompt
        self.config = config or AgentConfig()
        self.tracer = tracer or get_tracer()
        self.monitor = monitor

    def _render_prompt(self, mission: str, transcript: list[dict[str, object]]) -> str:
        parts = [
            f"MISSION:\n{mission}",
            f"\nAVAILABLE TOOLS:\n{self.registry.describe()}",
            f"\n{_PROTOCOL}",
        ]
        if transcript:
            parts.append("\nHISTORY (most recent last):")
            for entry in transcript[-12:]:
                parts.append(
                    f'  called {entry["tool"]}({entry["args"]}) -> {entry["observation"]}'
                )
        parts.append("\nWhat is your next action? Reply with one JSON tool call.")
        return "\n".join(parts)

    def run(self, mission: str) -> AgentResult:
        transcript: list[dict[str, object]] = []
        for step in range(self.config.max_steps):
            with self.tracer.span("agent_step", step=step):
                prompt = self._render_prompt(mission, transcript)
                response = self.router.complete(
                    self.config.role, CompletionRequest(prompt=prompt, system=self.system_prompt)
                )
                call = parse_tool_call(response.text)
                if call is None:
                    _log.info("agent produced no tool call at step %d; stopping", step)
                    return AgentResult("no_tool_call", step, transcript, summary=response.text)
                if call.name == "finish":
                    return AgentResult(
                        "finished", step, transcript, summary=str(call.args.get("summary", ""))
                    )
                result = self.registry.dispatch(call.name, call.args)
                observation = result.observation[: self.config.max_observation_chars]
                transcript.append(
                    {"tool": call.name, "args": call.args, "observation": observation}
                )
                self.tracer.counter("tool_calls")
                if self.monitor is not None:
                    note = self.monitor.observe(call.name, call.args)
                    if note:
                        transcript.append({"tool": "monitor", "args": {}, "observation": note})
        return AgentResult("max_steps", self.config.max_steps, transcript)
