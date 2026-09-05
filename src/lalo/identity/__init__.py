"""Identity, authentication, and the access-control role matrix.

Per-identity credential isolation (no shared state); multi-scheme login; deep JWT
handling; and a role matrix (endpoint x identity) that drives BOLA/IDOR/
function-level access-control testing. A session is mirrored onto the graph by
construction so cross-identity classes never silently starve for lack of a
visible session.
"""

from .jwt import decode_jwt, tamper_alg_none, tamper_claim
from .login import form_login, json_login
from .roles import build_role_matrix
from .store import IdentityStore, SessionMaterial, TokenStore

__all__ = [
    "IdentityStore",
    "SessionMaterial",
    "TokenStore",
    "build_role_matrix",
    "decode_jwt",
    "form_login",
    "json_login",
    "tamper_alg_none",
    "tamper_claim",
]
