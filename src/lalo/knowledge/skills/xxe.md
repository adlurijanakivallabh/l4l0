---
name: xxe
class: xxe
summary: XML External Entity injection — file read, SSRF, blind OOB exfil.
---
# XXE

## Attack surface
Any endpoint parsing XML: SOAP APIs, file uploads (docx/xlsx/svg are zipped XML),
SAML, RSS/Atom import, config import.

## Techniques
1. **Classic file read**: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>`
   referencing `&x;` in the body; content appears in the response = confirmed.
2. **Blind OOB**: entity SYSTEM URL = your OAST HTTP/DNS endpoint; poll for the
   callback (also proves SSRF-via-XXE for internal reach).
3. **OOB exfil of file content** (when direct reflection is blocked): a two-stage
   external DTD hosted on your own server that reads the file and appends it to a
   URL fetched back to your OAST/HTTP listener.
4. **SVG/DOCX/XLSX uploads**: embed the entity inside the zipped XML part.

## Proof ladder
- L1: XML accepted. L2: parser error suggests entity processing attempted.
- L3: file content returned OR OOB callback received. L4: sensitive file/cred
  disclosed, or internal SSRF pivot demonstrated.

## Validation
- A generic XML parse error is not XXE — require the entity's effect (content or
  callback). Some parsers disable external entities by default (libxml2 recent
  defaults) — confirm before assuming vulnerable.
