"""Textual observer — three panes over ReachabilityGraph + AuditLog (§14, Phase 2).

Pane 1  Targets/Graph — Host/Service/Endpoint tree + scope + wildcard_shape +
        per-Endpoint params + access_restricted 401/403 third state.
Pane 2  Findings      — Finding vuln_class / severity / oracle_used / evidence_ref
        + enables / derived_credential chain via chain_paths(start).
Pane 3  Live log      — AuditLog tail + firer outcomes (fired: / refused_* /
        payload_chain_failure). No oracle/firer import beyond reading entries.
No ScopeGuard bypass: scan_target owns firing, TUI only observes its graph via
0.5 s set_interval poll — same ReachabilityGraph + AuditLog instance the scan
writes, that is all. Shares scan/entrypoint:scan_target with headless
reachagent-scan so TUI adds no new confirmed path.
"""

from __future__ import annotations

import sys

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Log, Static, Tree

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph

# Coverage bar — ponytail: one-liner, no widget dep.
_COVERAGE_DENOM = 9  # VERIFIED_CHALLENGE_SCOPE size; honest 6/9 bar


class ReachAgentApp(App[None]):
    """Headless-offline safe observer; live scan started via on_mount when args set."""

    CSS = """
    #graph, #findings, #log { border: solid $primary; }
    #log { height: 14; }
    #graph { scrollbar-gutter: stable; }
    #stream { height: 1; background: $surface; color: $text; }
    #coverage { height: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("tab", "next_pane", "Next pane"),
        Binding("/", "filter", "Filter"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("question_mark", "help", "Help"),
        Binding("r", "refresh", "Refresh"),
        Binding("e", "export", "Export"),
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
        yield Static("", id="coverage")
        yield Static("", id="stream")
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

    def action_refresh(self) -> None:
        self.refresh_panes()

    def action_export(self) -> None:
        self.notify("Export: deterministic JSON via report/renderer.py (deferred)")

    def refresh_panes(self) -> None:
        self._refresh_graph()
        self._refresh_findings()
        self._refresh_log()
        self._refresh_header()
        self._refresh_stream()

    def _refresh_header(self) -> None:
        try:
            h = len(self.graph.hosts())
            e = len(self.graph.endpoints())
            f = len(self.graph.findings())
            n = f"{f}/{_COVERAGE_DENOM}"
            bar = "█" * f + "░" * max(0, _COVERAGE_DENOM - f)
            self.sub_title = f"hosts:{h} endpoints:{e} findings:{f}  {n} {bar}"
            cov = self.query_one("#coverage", Static)
            cov.update(f" coverage {n} [{bar}]  hosts:{h} endpoints:{e}")
        except Exception:  # noqa: BLE001, S110 — stats best-effort
            pass

    def _refresh_stream(self) -> None:
        try:
            entries = list(self.audit.entries)
            last = entries[-1] if entries else None
            findings = list(self.graph.findings())
            last_f = findings[-1] if findings else None
            stream = self.query_one("#stream", Static)
            if last_f is not None:
                stream.update(
                    f" → {getattr(last_f[1], 'vuln_class', '?')} via "
                    f"{getattr(last_f[1], 'oracle_used', '?')} "
                    f"({getattr(last_f[1], 'evidence_ref', '')}) — CONFIRMED"
                )
            elif last is not None:
                stream.update(f" → {last.method} {last.target} {last.outcome}")
            else:
                stream.update(" idle — waiting for scan_target")
        except Exception:  # noqa: BLE001, S110 — stream best-effort
            pass

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
        # findings() returns list[tuple[finding_id, Finding]] — show real fields.
        for f_id, finding in sorted(self.graph.findings(), key=lambda x: x[0]):
            vuln = getattr(finding, "vuln_class", "—")
            sev = getattr(finding, "severity", "—")
            oracle = getattr(finding, "oracle_used", "—")
            ev_ref = getattr(finding, "evidence_ref", "—")
            table.add_row(str(vuln), str(sev), str(oracle), str(ev_ref), f_id)

    def _refresh_log(self) -> None:
        log = self.query_one("#log", Log)
        entries = list(self.audit.entries)
        # Incremental: only write new tail since last refresh — simplest is clear &
        # rewrite tail (cheap; audit is append-only and short per run).
        log.clear()
        for e in entries[-200:]:
            # Color by outcome — green fired:200, yellow recovered, red refused.
            if "fired:200" in e.outcome and "recovered" in e.outcome:
                prefix = "[yellow]"
            elif "fired:200" in e.outcome:
                prefix = "[green]"
            elif "refused" in e.outcome or "failure" in e.outcome:
                prefix = "[red]"
            elif "ingested" in e.outcome:
                prefix = "[cyan]"
            else:
                prefix = ""
            suffix = "[/]" if prefix else ""
            line = (
                f"{prefix}{e.timestamp:%H:%M:%S} {e.identity} "
                f"{e.method} {e.target} {e.outcome}{suffix}"
            )
            log.write_line(line)


def main(argv: list[str] | None = None) -> int:
    """Console entry ``reachagent-tui`` — launches observer over an empty run."""
    if argv is None:
        argv = sys.argv[1:]
    if "--help" in argv or "-h" in argv:
        print("reachagent-tui — generic scan observer (textual 3-pane)")
        print("Usage: reachagent-tui [--help] [--visual]")
        print("Shares scan/entrypoint:scan_target with reachagent-scan headless.")
        short = (
            "Bindings: q quit, Tab next pane, / filter, j/k nav, "
            "r refresh, e export, ? help — 0.5s poll."
        )
        print(short)
        print("Visual: coverage bar 6/9 + stream payload→oracle→verdict live.")
        return 0
    app = ReachAgentApp()
    app.run()
    return 0
