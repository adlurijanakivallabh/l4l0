"""The autonomous agent: a think→act→observe loop over a free shell + tools.

The loop asks the LLM (via the multi-provider router) what to do next, parses a
tool call, executes it, feeds the observation back, and repeats until the agent
calls ``finish`` or hits a step/budget limit. Tools are injected, so the loop is
provider- and service-agnostic and fully testable with fakes.
"""

from .loop import AgentConfig, AgentLoop, AgentResult
from .tools import Tool, ToolCall, ToolRegistry, ToolResult, parse_tool_call

__all__ = [
    "AgentConfig",
    "AgentLoop",
    "AgentResult",
    "Tool",
    "ToolCall",
    "ToolRegistry",
    "ToolResult",
    "parse_tool_call",
]
