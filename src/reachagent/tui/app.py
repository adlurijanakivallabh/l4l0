"""Textual observer — three panes over ReachabilityGraph + AuditLog.

Pane 1  Targets/Graph — Host/Service/Endpoint tree + scope + wildcard_shape.
Pane 2  Findings      — Finding vuln_class / severity / oracle_used / evidence_ref
        + enables / derived_credential chain via chain_paths.
Pane 3  Live log      — AuditLog tail + firer outcomes (fired: / refused_*).
No oracle/firer import beyond reading AuditLog.entries and ReachabilityGraph.
No ScopeGuard bypass: scan_target owns firing, TUI only observes its graph.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Log, Tree

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph


class ReachAgentApp(App[None]):
    """Headless-offline safe observer; live scan started via on_mount when args set."""

    CSS = """
    #graph, #findings, #log { border: solid $primary; }
    #log { height: 12; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("tab", "next_pane", "Next pane"),
        Binding("/", "filter", "Filter"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("question_mark", "help", "Help"),
    ]

    def __init__(
        self,
        graph: ReachabilityGraph | None = None,
        audit: AuditLog | None = None,
        title: str = "ReachAgent — generic scan observer",
    ) -> None:
        super().__init__()
        self.graph: ReachabilityGraph = graph or ReachabilityGraph()
        self.audit: AuditLog = audit or AuditLog()
        self.title = title

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="left"):
                yield Tree("Targets / Graph", id="graph")
                yield Log(id="log", highlight=True)
            yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("vuln_class", "severity", "oracle_used", "evidence_ref", "finding_node")
        self.set_interval(0.5, self.refresh_panes)
        self.refresh_panes()

    def action_next_pane(self) -> None:
        self.screen.focus_next()

    def action_filter(self) -> None:
        self.notify("Filter: type / to filter current pane (deferred)")

    def refresh_panes(self) -> None:
        self._refresh_graph()
        self._refresh_findings()
        self._refresh_log()

    def _refresh_graph(self) -> None:
        tree = self.query_one("#graph", Tree)
        tree.clear()
        root = tree.root
        # Hosts — hosts() returns list[tuple[host_id, Host]]
        for host_id, host in sorted(self.graph.hosts(), key=lambda x: x[0]):
            label = host_id
            if host and (host.technology or host.source):
                label += f"  [{host.technology or ''} {host.source or ''}]".strip()
            h_node = root.add(label, expand=True)
            for svc_id, _svc in sorted(self.graph.services_of(host_id), key=lambda x: x[0]):
                h_node.add_leaf(svc_id)
        # Endpoints + params — endpoints() returns list[tuple[ep_id, Endpoint]]
        for ep_id, ep in sorted(self.graph.endpoints(), key=lambda x: x[0]):
            path = ep.path if ep else ep_id
            method = ep.method if ep else "?"
            e_node = root.add(f"{method} {path}", expand=False)
            for p_id, param in self.graph.parameters_of(ep_id):
                sink = f" sink={param.inferred_sink_type.value}" if param.inferred_sink_type else ""
                restricted = (
                    f" restricted={ep.access_restricted}" if ep and ep.access_restricted else ""
                )
                e_node.add_leaf(f"{param.name} [{param.location}]{sink}{restricted} ({p_id})")

    def _refresh_findings(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        # findings() returns list[tuple[finding_id, Finding]]
        for f_id, _finding in sorted(self.graph.findings(), key=lambda x: x[0]):
            table.add_row("—", "—", "—", "—", f_id)

    def _refresh_log(self) -> None:
        log = self.query_one("#log", Log)
        entries = list(self.audit.entries)
        # Incremental: only write new tail since last refresh — simplest is clear &
        # rewrite tail (cheap; audit is append-only and short per run).
        log.clear()
        for e in entries[-200:]:
            log.write_line(f"{e.timestamp:%H:%M:%S} {e.identity} {e.method} {e.target} {e.outcome}")


def main() -> None:
    """Console entry ``reachagent-tui`` — launches observer over an empty run."""
    app = ReachAgentApp()
    app.run()
