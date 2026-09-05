"""Identity: per-identity credentials, multi-scheme login, JWT tools, role matrix."""

from .credentials import Credential, CredentialKind, Identity, IdentityStore
from .jwt_tools import DecodedJwt, jwt_alg_none, jwt_decode, jwt_with_claim
from .login import BodyEncoding, LoginScheme, Session, SessionRegistry, SessionSource, login
from .role_matrix import RoleMatrixEntry, build_role_matrix

__all__ = [
    "BodyEncoding",
    "Credential",
    "CredentialKind",
    "DecodedJwt",
    "Identity",
    "IdentityStore",
    "LoginScheme",
    "RoleMatrixEntry",
    "Session",
    "SessionRegistry",
    "SessionSource",
    "build_role_matrix",
    "jwt_alg_none",
    "jwt_decode",
    "jwt_with_claim",
    "login",
]
