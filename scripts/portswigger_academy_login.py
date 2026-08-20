#!/usr/bin/env python3
"""
PortSwigger Academy login + lab launcher.

Reads REACHAGENT_PORTSWIGGER_EMAIL / REACHAGENT_PORTSWIGGER_PASSWORD from env,
logs in via Auth0 Universal Login (https://login.portswigger.net/u/login) with
headless chromium (playwright async_api), navigates to the blind SQLi
time-delay lab, clicks "Access the lab", captures the resulting lab URL
https://<id>.web-security-academy.net and its session cookie value, and prints

  export REACHAGENT_PORTSWIGGER_LAB_URL='...'
  export REACHAGENT_PORTSWIGGER_SESSION_TOKEN='...'

to stdout (suitable for eval $(...)). Logs go to stderr. Never prints the
password. Returns precise failure reason if Academy structure changed (selector,
CSRF state, 504, timeout, etc).

Constraints from task:
  - env only, no hard-coded credentials
  - handle Academy CSRF tokens (Auth0 state param)
  - wait for lab iframe/redirect or popup
  - report LAB_URL+TOKEN or failure reason
"""

from __future__ import annotations

import asyncio
import os
import re
import sys

LAB_PAGE = "https://portswigger.net/web-security/sql-injection/blind/lab-time-delays"
LOGIN_ENTRY = "https://portswigger.net/users"
LAB_HOST_RE = re.compile(r"https://[a-z0-9]+\.web-security-academy\.net/?", re.I)

# Auth0 Universal Login selectors (verified 2026-08-20 via httpx probe)
SEL_USERNAME = "#username"
SEL_PASSWORD = "#password"  # noqa: S105 — CSS selector, not a credential
SEL_SUBMIT = 'button[data-action-button-primary="true"][name="action"], button[type="submit"]'
SEL_ERROR = ".ulp-error-info, [data-error-code], .error-message, #ulp-error-announcer"

# Lab launcher selectors — widget is JS-rendered after auth; probe multiple
LAB_SELECTORS = [
    '[widget-id="academy-launchlab"] a',
    '[widget-id="academy-launchlab"] button',
    'a:has-text("Access the lab")',
    'button:has-text("Access the lab")',
    "a.lab-link",
    'a:has-text("View lab")',
    'iframe[src*="web-security-academy.net"]',
]

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _fail(msg: str, code: int = 1) -> None:
    print(f"FAIL: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


async def run() -> None:
    email = (os.environ.get("REACHAGENT_PORTSWIGGER_EMAIL") or "").strip()
    password = (os.environ.get("REACHAGENT_PORTSWIGGER_PASSWORD") or "").strip()

    if not email:
        _fail(
            "REACHAGENT_PORTSWIGGER_EMAIL not set or empty — set it in env (never hard-code)",
            2,
        )
    if not password:
        _fail("REACHAGENT_PORTSWIGGER_PASSWORD not set or empty — set it in env", 2)

    if "@" not in email:
        print(f"WARN: email {email!r} does not look like an email", file=sys.stderr)

    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        _fail(
            "playwright not installed — run: uv sync "
            "&& uv run playwright install chromium "
            "(pyproject requires playwright>=1.61)"
        )

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=UA,
        )
        page = await context.new_page()

        # --- 1) Login -----------------------------------------------------
        print(f"[*] navigating to {LOGIN_ENTRY}", file=sys.stderr, flush=True)
        try:
            await page.goto(LOGIN_ENTRY, wait_until="domcontentloaded", timeout=20000)
        except Exception as e:
            _fail(f"goto {LOGIN_ENTRY} failed: {e}")

        # May redirect to https://login.portswigger.net/u/login?state=...
        # Wait for the Auth0 Universal Login form.
        print(
            f"[*] waiting for Auth0 login form ({SEL_USERNAME})",
            file=sys.stderr,
            flush=True,
        )
        try:
            await page.wait_for_selector(SEL_USERNAME, timeout=20000)
        except Exception:
            url = page.url
            content = (await page.content())[:4000].replace("\n", " ")
            _fail(
                "CSRF selector failure — #username not found. "
                f"Current URL: {url}. "
                "Login page structure may have changed "
                "(Auth0 Universal Login version bump?). "
                f"Snippet: {content[:1500]}. "
                "Hint: re-probe with: curl -H 'User-Agent: Mozilla/5.0' "
                "https://portswigger.net/users "
                "and inspect login.portswigger.net form"
            )

        await page.fill(SEL_USERNAME, email)
        await page.wait_for_timeout(300)
        try:
            await page.wait_for_selector(SEL_PASSWORD, timeout=5000)
        except Exception:
            _fail(
                "password selector #password not found after email fill "
                "— login form structure changed"
            )
        await page.fill(SEL_PASSWORD, password)

        print("[*] submitting Auth0 form", file=sys.stderr, flush=True)
        submit_btn = await page.wait_for_selector(SEL_SUBMIT, timeout=5000)
        if submit_btn is None:
            _fail("submit button data-action-button-primary not found — selector changed")

        # Auth0 may use JS XHR then redirect; wait for navigation away
        try:
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=25000):
                await submit_btn.click()
        except Exception:
            await page.wait_for_timeout(2500)

        # Check for visible error (bad creds, rate-limit, captcha)
        await page.wait_for_timeout(1500)
        error_el = await page.query_selector(SEL_ERROR)
        if error_el is not None:
            err_text = (await error_el.inner_text() or "").strip()[:500]
            if err_text and "please enter" not in err_text.lower():
                print(
                    f"[!] login form error text: {err_text!r}",
                    file=sys.stderr,
                    flush=True,
                )
                if "login.portswigger.net" in page.url:
                    _fail(
                        "login failed — Auth0 rejected credentials or "
                        f"captcha required. Text: {err_text!r}  url={page.url}"
                    )

        cur = page.url
        print(f"[*] post-login URL: {cur}", file=sys.stderr, flush=True)
        if "login.portswigger.net" in cur:
            snippet = (await page.content())[:3000].replace("\n", " ")
            if "recaptcha" in snippet.lower() or "captcha" in snippet.lower():
                _fail(
                    f"login blocked by CAPTCHA/recaptcha at {cur} "
                    "— manual solve required (headless cannot pass). "
                    f"Snippet: {snippet[:1200]}"
                )
            _fail(
                "still on Auth0 after submit — likely bad credentials "
                f"or login flow changed. url={cur} snippet={snippet[:1200]}"
            )

        await page.goto(
            "https://portswigger.net/web-security/dashboard",
            wait_until="domcontentloaded",
            timeout=15000,
        )
        if "login.portswigger.net" in page.url:
            _fail(f"not authenticated after login — redirect back to Auth0 at {page.url}")

        # --- 2) Navigate to lab page --------------------------------------
        print(f"[*] navigating to lab page {LAB_PAGE}", file=sys.stderr, flush=True)
        await page.goto(LAB_PAGE, wait_until="domcontentloaded", timeout=20000)
        await page.wait_for_timeout(2500)  # widget is JS-rendered

        widget_present = await page.query_selector('[widget-id="academy-launchlab"]')
        if widget_present is None:
            print(
                "[!] widget academy-launchlab not found — page structure changed",
                file=sys.stderr,
                flush=True,
            )
        else:
            html = (await widget_present.inner_html())[:2000].replace("\n", " ")
            print(
                f"[*] launchlab widget html snippet: {html[:1200]}",
                file=sys.stderr,
                flush=True,
            )

        launcher = None
        launcher_selector_used = ""
        for sel in LAB_SELECTORS:
            try:
                cand = await page.query_selector(sel)
                if cand is not None and await cand.is_visible():
                    launcher = cand
                    launcher_selector_used = sel
                    break
            except Exception as e:  # noqa: S112 — probe multiple selectors
                print(f"[!] selector {sel!r} probe failed: {e}", file=sys.stderr)
                continue

        if launcher is None:
            for txt in ["Access the lab", "View lab", "Launch lab"]:
                try:
                    cand = page.get_by_text(txt, exact=False).first
                    if await cand.count() > 0 and await cand.is_visible():
                        launcher = cand
                        launcher_selector_used = f"text={txt}"
                        break
                except Exception as e:  # noqa: S112 — fallback text search
                    print(f"[!] text {txt!r} probe failed: {e}", file=sys.stderr)
                    continue

        # Check for already-running lab (lab URL already embedded)
        lab_url: str | None = None
        for el in await page.query_selector_all(
            'a[href*="web-security-academy.net"], iframe[src*="web-security-academy.net"]'
        ):
            try:
                href = (await el.get_attribute("href")) or (await el.get_attribute("src")) or ""
                m = LAB_HOST_RE.search(href)
                if m:
                    lab_url = m.group(0).rstrip("/") + "/"
                    print(
                        f"[*] lab URL already embedded without click: {lab_url}",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
            except Exception as e:  # noqa: S112 — best-effort harvest
                print(f"[!] href harvest failed: {e}", file=sys.stderr)
                continue

        if lab_url is None and launcher is None:
            snippet = (await page.content())[:5000].replace("\n", " ")
            widget_html = ""
            if widget_present is not None:
                try:
                    widget_html = await widget_present.inner_html()
                except Exception:
                    widget_html = "unreadable"
            _fail(
                f"lab launcher selector failure — none of {LAB_SELECTORS} matched. "
                f"Widget snippet: {widget_html[:800]} "
                f"Page snippet: {snippet[:2000]}. "
                "Hint: unauthenticated lab pages are empty (JS widget). "
                "If not authenticated, login failed above. "
                f"Re-probe: curl -H 'Cookie: session=...' {LAB_PAGE}"
            )

        # --- 3) Click to launch lab, capture lab URL -----------------------
        if lab_url is None:
            print(
                f"[*] clicking launcher ({launcher_selector_used})",
                file=sys.stderr,
                flush=True,
            )
            popup_captured: list = []

            def _on_popup(popup):
                popup_captured.append(popup)

            context.on("page", _on_popup)

            lab_urls_seen: list[str] = []

            def _on_request(req):
                url = req.url
                if LAB_HOST_RE.search(url):
                    lab_urls_seen.append(url)

            page.on("request", _on_request)

            try:
                await launcher.click(timeout=10000)
            except Exception as e:
                _fail(f"click on lab launcher failed ({launcher_selector_used}): {e}")

            lab_url = None
            deadline = asyncio.get_event_loop().time() + 25
            while asyncio.get_event_loop().time() < deadline:
                for popup in popup_captured:
                    try:
                        await popup.wait_for_load_state("domcontentloaded", timeout=2000)
                        u = popup.url
                        m = LAB_HOST_RE.search(u)
                        if m:
                            lab_url = m.group(0).rstrip("/") + "/"
                            page = popup
                            break
                    except Exception:  # noqa: S110 — popup not ready yet
                        pass
                if lab_url:
                    break
                for el in await page.query_selector_all('iframe[src*="web-security-academy.net"]'):
                    src = (await el.get_attribute("src")) or ""
                    m = LAB_HOST_RE.search(src)
                    if m:
                        lab_url = m.group(0).rstrip("/") + "/"
                        break
                if lab_url:
                    break
                for el in await page.query_selector_all('a[href*="web-security-academy.net"]'):
                    href = (await el.get_attribute("href")) or ""
                    m = LAB_HOST_RE.search(href)
                    if m:
                        lab_url = m.group(0).rstrip("/") + "/"
                        break
                if lab_url:
                    break
                for u in lab_urls_seen:
                    m = LAB_HOST_RE.search(u)
                    if m:
                        lab_url = m.group(0).rstrip("/") + "/"
                        break
                if lab_url:
                    break
                m = LAB_HOST_RE.search(page.url)
                if m:
                    lab_url = m.group(0).rstrip("/") + "/"
                    break
                await asyncio.sleep(0.6)

            if lab_url is None:
                for popup in popup_captured:
                    m = LAB_HOST_RE.search(popup.url)
                    if m:
                        lab_url = m.group(0).rstrip("/") + "/"
                        page = popup
                        break
                if lab_url is None:
                    snippet = (await page.content())[:3000].replace("\n", " ")
                    _fail(
                        "lab URL not captured after click — no popup/iframe/"
                        f"navigation matched {LAB_HOST_RE.pattern}. "
                        f"popup_count={len(popup_captured)} "
                        f"popup_urls={[p.url for p in popup_captured]} "
                        f"seen_requests={lab_urls_seen[:5]} cur_url={page.url} "
                        f"snippet={snippet[:1200]}. "
                        "Possible causes: lab 504, rate-limit, or Academy "
                        "widget changed."
                    )

        lab_url = lab_url.rstrip("/")
        print(f"[*] captured lab URL: {lab_url}", file=sys.stderr, flush=True)

        # --- 4) Capture session cookie ------------------------------------
        await asyncio.sleep(1.5)
        try:
            await page.goto(lab_url + "/", wait_until="domcontentloaded", timeout=15000)
        except Exception as e:
            print(
                f"[!] GET {lab_url}/ after launch got: {e} — still trying to read cookies",
                file=sys.stderr,
                flush=True,
            )

        if "Gateway Timeout" in (await page.content())[:2000]:
            print(
                f"[!] lab {lab_url} returned 504 Gateway Timeout "
                "— lab warming up or expired; cookie may still be valid",
                file=sys.stderr,
                flush=True,
            )

        cookies = await context.cookies()
        token: str | None = None
        for c in cookies:
            if c.get("name") == "session" and "web-security-academy.net" in c.get("domain", ""):
                lab_host = lab_url.split("//", 1)[-1].split("/", 1)[0]
                if lab_host in c.get("domain", "") or lab_host == c.get("domain", "").lstrip("."):
                    token = c.get("value")
                    break
                if token is None:
                    token = c.get("value")

        if not token:
            domains = sorted({f"{c['name']}@{c['domain']}" for c in cookies})
            _fail(
                "session cookie not found after lab launch — Academy may have "
                f"changed cookie name. lab_url={lab_url} "
                f"cookie_names/domains={domains[:20]} cur_url={page.url}"
            )

        # --- 5) Emit exports (stdout only, no password/extra logs) -------
        def sq(s: str) -> str:
            return s.replace("'", "'\\''")

        print(f"export REACHAGENT_PORTSWIGGER_LAB_URL='{sq(lab_url)}'")
        print(f"export REACHAGENT_PORTSWIGGER_SESSION_TOKEN='{sq(token)}'")
        print(
            "[*] done — lab ready for REACHAGENT_PORTSWIGGER_LIVE=1 harness",
            file=sys.stderr,
            flush=True,
        )

        await browser.close()


if __name__ == "__main__":
    asyncio.run(run())
