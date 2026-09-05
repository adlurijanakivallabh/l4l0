---
name: access_control
class: access_control
summary: Prove BOLA/IDOR, broken function-level authz, and mass assignment (cross-identity).
---
# Broken Access Control (BOLA/IDOR, function-level, mass assignment)

The #1 API risk. Proven by accessing another tenant's object or a
higher-privilege function using a LOWER-privilege identity — a cross-identity
differential, so you need ≥2 identities.

## Setup (mandatory)
- Obtain session material for at least two identities: two normal users (A, B)
  in different tenants, and ideally one privileged (admin) token. L4L0's identity
  store holds these; the role matrix = every endpoint × every identity.

## Techniques
- **BOLA/IDOR**: enumerate object references (numeric ids, UUIDs, filenames,
  account/order/doc ids). Request A's object id using B's token; access = vuln.
  Vary location: path, query, body, headers, GraphQL node ids.
- **Broken function-level authz**: call admin/privileged endpoints
  (`/admin/*`, `DELETE`, `PUT`, method-override) with a normal token; success = vuln.
- **Mass assignment / BOPLA**: add privileged fields to a request body
  (`"role":"admin"`, `"isVerified":true`, `"balance":9999`, `"tenantId":<other>`);
  re-read to confirm the server accepted them.
- **Missing object-level filter on writes**: update/delete another user's object.

## Method (systematic)
- For each endpoint, replay the SAME request under each identity and diff:
  same data returned to B as to A (for A's object) = broken isolation.
- Compare unauth vs auth vs cross-tenant vs admin responses.

## Proof ladder
- L1: an id/field is guessable/enumerable. L2: response differs by identity in a
  suspicious way. L3: identity B reads/writes identity A's object, or a normal
  user invokes a privileged function (demonstrated). L4: full tenant takeover /
  admin action as a normal user.

## Validation / false positives
- Prove it's cross-identity: show A's object is returned to B's token AND that
  B legitimately shouldn't see it (compare to B's own object).
- 200 with empty/placeholder data is not access — confirm real other-tenant data.
- Rule out "both users are in the same org/shared resource by design."
