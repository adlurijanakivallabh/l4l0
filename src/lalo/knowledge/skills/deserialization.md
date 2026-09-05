---
name: deserialization
class: deserialization
summary: Insecure deserialization — Java/PHP/.NET/Python gadget chains toward RCE.
---
# Insecure Deserialization

## Attack surface
- Java: serialized objects in cookies/params/headers (base64 `rO0AB...` prefix),
  RMI/JMX endpoints.
- PHP: `unserialize()` on cookies/session/cache values (look for `O:` / `a:` shapes).
- .NET: `ViewState`, `BinaryFormatter`, JSON.NET `TypeNameHandling`.
- Python: `pickle`/`yaml.load` on untrusted input, `__reduce__` gadgets.

## Techniques
- Identify the format from the raw bytes/shape.
- For known frameworks, use `ysoserial`(Java)/`ysoserial.net` gadget chains
  fired via the free shell; for PHP, craft an object with a known gadget class
  present in the app's dependencies (phpggc-style chains).
- Prove via OOB callback (gadget triggers a DNS/HTTP request to OAST) before
  attempting in-band command execution.

## Proof ladder
- L1: serialized-shaped input accepted. L2: deserialization error suggests
  processing (type-confusion exception, not a generic 400).
- L3: OOB callback fired from a gadget chain = deserialization confirmed.
- L4: command execution proven (id/canary) via a full RCE gadget.

## Validation
- A parse error alone is not proof — the OOB callback or command output is what
  distinguishes "accepts the format" from "unsafely deserializes untrusted data."
