"""Reachability graph — the shared system of record (plan §6).

Two layers, kept separate so chaining stays generic (§6):
  * structural facts   — what the app actually does
  * finding relationships — how confirmed vulnerabilities connect

Phase 1–2 backing store is NetworkX in-process; migrates to Neo4j once
finding-relationship chain queries become the bottleneck (§12).
"""
