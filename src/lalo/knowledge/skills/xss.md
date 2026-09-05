---
name: xss
class: xss
summary: Find, exploit, and prove reflected, stored, and DOM XSS (context-driven).
---
# Cross-Site Scripting

XSS is proven by demonstrating attacker-controlled script *execution* in a
victim's browser context — not mere reflection.

## Attack surface
- Reflected: any input echoed into a response (search, error messages, headers).
- Stored: input persisted then rendered (comments, profile, filenames, logs/admin views).
- DOM: client-side sinks — `innerHTML`, `document.write`, `eval`, `location`,
  `postMessage` handlers, template frameworks, `dangerouslySetInnerHTML`.

## Recon
- Inject a unique marker (`lalo7f3a`); find WHERE and HOW it is encoded in the
  response (HTML body, attribute value, JS string, URL, CSS, comment).
- For DOM: read the JS, trace source (location/hash/postMessage) → sink; the
  browser tool confirms actual execution.

## Techniques by context (minimal breakout)
- HTML body: `<script>...</script>`, `<img src=x onerror=...>`, `<svg onload=...>`.
- Attribute: close it first — `"><svg onload=...>` or `" onmouseover=...`.
- JS string: `';alert(1)//` / `</script>` breakout.
- URL/href: `javascript:` scheme.
- Filter bypass: case, encoding, split tags, event handlers, `srcdoc`, mutation-XSS.
- WAF bypass: try alternate tags/events, HTML-entity/unicode, no-parens payloads.
- Blind/stored-elsewhere (admin panel): OOB beacon — `<img src=OAST_URL>` /
  `fetch('OAST_URL')` — and poll the OAST server for the callback.

## Proof ladder
- L1: payload accepted.
- L2: reflected UNENCODED in an executable context (but execution not shown).
- L3: execution confirmed — a headless browser runs the payload (alert/DOM change),
  or an OOB beacon fires from the rendering page.
- L4: session/account impact demonstrated (cookie/token theft to OAST, action-as-victim).

## Validation / false positives
- Reflection with HTML-encoding (`&lt;script&gt;`) is NOT XSS.
- JSON/`application/json` responses do not execute HTML — not XSS unless a sink
  renders them as HTML.
- Prefer browser-confirmed execution or an OOB callback over "the payload appears
  in the body." `dalfox` can exhaust contexts; treat its hits as candidates to confirm.
