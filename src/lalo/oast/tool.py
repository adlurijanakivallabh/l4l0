"""``issue_oast_probe``/``poll_oast`` — agent tools over the self-hosted OAST server.

Wraps Phase 4's :class:`~lalo.oast.server.OASTServer` (confirmed original —
no reference bundles a genuinely integrated, self-hosted callback+correlation
mechanism into its own confirmation pipeline). Tool-interface wiring only —
issue a token/callback value, embed it in a payload via your own judgment,
fire it, then poll the same token for a correlated hit.
"""

from __future__ import annotations

from ..agent.tools import FunctionTool, ToolResult, str_arg
from .server import OASTServer


def build_oast_tools(oast: OASTServer) -> tuple[FunctionTool, FunctionTool]:
    def _issue(args: dict[str, object]) -> ToolResult:
        probe_ref = args.get("probe_ref")
        token = oast.issue_token(str(probe_ref) if probe_ref else None)
        observation = (
            f"token={token}\n"
            f"http_callback_url={oast.callback_url(token)}\n"
            f"dns_callback_hostname={oast.dns_name(token)}"
        )
        return ToolResult(observation=observation)

    def _poll(args: dict[str, object]) -> ToolResult:
        token = str_arg(args, "token").strip()
        if not token:
            return ToolResult(observation="error: 'token' is required", ok=False)
        hits = oast.poll(token)
        if not hits:
            return ToolResult(observation=f"no interactions yet for token {token}", ok=False)
        lines = [f"{hit.kind} from {hit.source}: {hit.detail}" for hit in hits]
        return ToolResult(observation="\n".join(lines))

    issue_tool = FunctionTool(
        name="issue_oast_probe",
        description=(
            "Issue a fresh out-of-band callback token/URL/hostname to embed in a payload for "
            'blind vulnerability confirmation. args: {"probe_ref": str (optional, your own label)}'
        ),
        func=_issue,
    )
    poll_tool = FunctionTool(
        name="poll_oast",
        description=(
            "Check whether a token you issued has received any out-of-band callback yet. "
            'args: {"token": str}'
        ),
        func=_poll,
    )
    return issue_tool, poll_tool
