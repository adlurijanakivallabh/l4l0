---
name: jwt
class: jwt
summary: JWT/session-token attacks (alg confusion, kid/jku/x5u, weak secret, claims).
---
# JWT & Token Attacks

## Recon
- Decode the token (base64url header.payload.signature); note `alg`, `kid`,
  `jku`/`x5u`, claims (role/scope/exp/sub).

## Techniques
- **alg:none**: strip the signature, set `alg:"none"`, submit — many libraries
  historically accept an empty signature.
- **alg confusion (RS256→HS256)**: if the server uses the RSA public key to
  verify, re-sign an HS256 token using the PUBLIC KEY as the HMAC secret.
- **kid injection**: `kid` often selects the verification key/file — try path
  traversal (`../../dev/null` → empty key) or SQL injection in the kid lookup.
- **jku/x5u header injection**: point at an attacker-hosted JWK set/cert; if the
  server fetches and trusts it, forge any token (also an SSRF vector — use OAST).
- **Weak secret (HS256)**: brute-force common/weak secrets with `jwt_tool`/hashcat.
- **Claim tampering**: change `sub`/`role`/`tenant` and see if a weak/expired
  signature check still accepts it (`exp` not enforced, `aud` not checked).
- Use the identity module's `tamper_alg_none`/`tamper_claim` helpers to build
  variants; fire them and observe whether the server accepts the tampered token.

## Proof ladder
- L1: token structure understood. L2: a tampered token is accepted by the
  transport layer without a 401. L3: a forged/tampered token grants access to
  data/actions it shouldn't. L4: full auth bypass as an arbitrary user/admin.

## Validation
- Confirm the SERVER, not just a proxy/cache, is accepting the tampered token —
  check the actual authenticated response content changed accordingly.
