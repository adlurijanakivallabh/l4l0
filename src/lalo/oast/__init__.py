"""Self-hosted out-of-band application security testing (OAST) server.

Issues unique per-probe tokens and listens for HTTP + DNS callbacks to them, so
blind vulnerabilities (blind SSRF/XXE/RCE/SQLi/XSS) that produce no visible
response are still caught. Each interaction correlates back to the probe that
issued its token. No dependency on any public collaborator service.
"""

from .server import Interaction, OASTServer

__all__ = ["Interaction", "OASTServer"]
