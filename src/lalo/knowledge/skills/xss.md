---
name: xss
class: xss
summary: Methodology for reflected, stored, and DOM XSS.
---
# Cross-Site Scripting

1. Identify the reflection context: HTML body, attribute, JS string, URL, or DOM sink.
2. Inject a unique marker; find where and how it is encoded in the response.
3. Break out of the context with the minimal payload: `<script>` in HTML body,
   `"><svg onload=...>` in an attribute, `';alert(1)//` in a JS string.
4. Stored: submit, then re-fetch the rendering page to confirm persistence.
5. DOM: trace the source→sink in client JS (a headless browser confirms execution).
6. Blind/stored-elsewhere: use an OOB `fetch()`/image beacon to the OAST URL.

Confidence: an unencoded reflection in an executable context that a browser runs
(or an OOB beacon fires) is strong; mere reflection without breakout is weak.
