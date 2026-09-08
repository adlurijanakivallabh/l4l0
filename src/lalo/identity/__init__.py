"""Identity: per-identity credentials, multi-scheme login, JWT tools, role matrix."""

from .credentials import Credential, CredentialKind, Identity, IdentityStore
from .jwt_tools import DecodedJwt, jwt_alg_none, jwt_crack_secret, jwt_decode, jwt_with_claim
from .login import BodyEncoding, LoginScheme, Session, SessionRegistry, SessionSource, login
from .role_matrix import RoleMatrixEntry, build_role_matrix
from .tool import build_jwt_tool, build_login_tool, build_session_check_tool
from .totp import generate_totp

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
    "build_jwt_tool",
    "build_login_tool",
    "build_session_check_tool",
    "build_role_matrix",
    "generate_totp",
    "jwt_alg_none",
    "jwt_crack_secret",
    "jwt_decode",
    "jwt_with_claim",
    "login",
]
