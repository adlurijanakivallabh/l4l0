"""Self-hosted out-of-band application security testing (OAST) server.

Original — confirmed via each reference project's own comparison
documentation, across all five, that none builds an integrated,
self-hosted OAST mechanism (one
bundles a third-party OOB client as an external tool the agent may invoke, but
nothing wires automatic per-probe token issuance + interaction correlation into
its own confirmation pipeline the way this module does).

Issues unique per-probe tokens and listens for HTTP + DNS callbacks to them, so
blind vulnerabilities (blind SSRF/XXE/RCE/SQLi/XSS) that produce no visible
response are still caught. Each interaction correlates back to the probe that
issued its token. No dependency on any public collaborator service.
"""

from .server import Interaction, OASTServer
from .tool import build_oast_tools

__all__ = ["Interaction", "OASTServer", "build_oast_tools"]
