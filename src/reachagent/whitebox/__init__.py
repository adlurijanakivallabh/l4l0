"""White-box (source-available) testing mode — Build Order 7.

Additive to, never a replacement for, the existing live-HTTP black-box scan
(§1, §9). Off unless the operator supplies a repo path. Static tools here are
fact-emitters, same architectural role as the recon tier
(:mod:`reachagent.recon.tools`) — they never write a ``Finding`` or call
``run_oracle``, with one narrow, explicit, structurally-separate exception
(:class:`~reachagent.graph.nodes.StaticAdvisory` — see ``sca.py``).
"""
