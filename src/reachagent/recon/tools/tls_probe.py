"""TLS probes — testssl/sslscan/sslyze as Host fact-emitters (§9 recon tier).

TLS decision (see module docstring top-of-file):
  Option 2 chosen — weak TLS does NOT cleanly fit STRUCTURAL's current evidence
  shape. STRUCTURAL's confirmable checks (clickjacking/CORS/CSRF) are all
  pure header/body string decisions over a single recorded fire (XFO, CSP,
  ACAO/ACAC, Set-Cookie). A TLS finding would need per-handshake
  protocol/cipher/ALPN fields from a TLS negotiation, not an HTTP header/body —
  stretching STRUCTURAL to "tls protocol string contains TLSv1.0" would conflate
  transport negotiation state with response-header presence and would tempt a
  synthetic "header" to make the shape fit. That stretches the model, not uses
  it.

  So: all three runners land Host attributes (technology/detected_version
  extension encoding supported protocols/ciphers) as facts only. No new
  StructuralCheckType, no new OracleMechanism, no run_oracle/write_finding path.

  # detection pending oracle design — facts only, see task report

Facts only — same tier as whatweb: never a Technology node, never a candidate.
"""

from __future__ import annotations

import json
import re
from typing import Any

from defusedxml.ElementTree import fromstring

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner

# ---------------------------------------------------------------------------
# Shared helper — one place that materializes TLS facts onto a Host node
# ---------------------------------------------------------------------------


def _tls_facts_to_host(
    graph: Any,  # ReachabilityGraph — keep import light, avoid circular
    host_addr: str,
    protocols: list[str],
    ciphers: list[str],
    source: str,
) -> str:
    """Write deprecated/negotiated TLS facts as Host.technology/detected_version.

    Encoded as comma-joined attribute strings on the one Host node (facts only,
    §6: attributes not Technology nodes). Returns the host node id.
    """
    # Filter to non-empty, dedup, stable order for deterministic graph snapshot
    protos = sorted({p.strip() for p in protocols if p.strip()})
    cips = sorted({c.strip() for c in ciphers if c.strip()})
    tech_parts: list[str] = []
    if protos:
        tech_parts.append(f"tls:protocols={','.join(protos)}")
    if cips:
        tech_parts.append(f"tls:ciphers={','.join(cips[:8])}")
    technology = ", ".join(tech_parts) or None
    # detected_version repurposed as "most modern protocol seen" when available
    detected_version = protos[-1] if protos else None
    return str(
        graph.add_host(
            Host(
                address=host_addr,
                hostname=host_addr,
                source=source,
                technology=technology,
                detected_version=detected_version,
            )
        )
    )


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------

# testssl JSON: {"scanResult":[{"targetHost":...,
#   "protocols":[{"id":"TLS1_2","severity":"OK"}]}]} — also bare list tolerated


class TestsslRunner(ReconToolRunner):
    """Emit TLS protocol/cipher Host facts from testssl.sh JSON (§9). Facts only."""

    name = "testssl"
    binary = "testssl.sh"

    def command(self, target: str) -> list[str]:
        """testssl.sh --jsonfile - <target> — JSON findings to stdout/file."""
        return ["testssl.sh", "--jsonfile", "-", target]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse testssl JSON — protocols with findings[].id like TLS1_0/TLS1_2."""
        written: list[str] = []
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return ()
        # testssl wraps as {"scanResult": [...]} or bare list
        results = parsed.get("scanResult", parsed) if isinstance(parsed, dict) else parsed
        if not isinstance(results, list):
            results = [results] if isinstance(results, dict) else []
        protocols: list[str] = []
        ciphers: list[str] = []
        host_addr = _host_of(target)
        for entry in results:
            if not isinstance(entry, dict):
                continue
            findings = entry.get("findings", entry.get("protocols", []))
            if isinstance(findings, list):
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    fid = str(finding.get("id", finding.get("protocol", "")))
                    sev = str(finding.get("severity", finding.get("finding", "")))
                    # Keep enabled/warned protocols, not just severities
                    if fid.startswith("TLS") or fid.startswith("SSL"):
                        protocols.append(fid)
                        if "cipher" in fid.lower():
                            ciphers.append(fid)
                        # Also scavenge cipher field
                        if finding.get("cipher"):
                            ciphers.append(str(finding["cipher"]))
                    # Fallback: raw id is protocol name
                    if sev and fid and fid not in protocols:
                        protocols.append(fid)
            # Also handle flat keys like "TLS1_0": "offered"
            for key in ("TLS1_0", "TLS1_1", "TLS1_2", "TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv3"):
                if key in entry and str(entry[key]).lower() in (
                    "offered",
                    "enabled",
                    "ok",
                    "yes",
                    "true",
                ):
                    protocols.append(key)
        if not protocols and not ciphers:
            # Last resort: regex scan for protocol tokens in raw text
            for token in re.findall(r"TLSv?1[._][012]|SSLv?3", raw_output):
                protocols.append(token)
        host_addr = _host_of(target)
        node = _tls_facts_to_host(self.graph, host_addr, protocols, ciphers, self.name)
        written.append(node)
        return tuple(written)


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------


class SslscanRunner(ReconToolRunner):
    """Emit TLS cipher/protocol Host facts from sslscan XML (§9). Facts only."""

    name = "sslscan"
    binary = "sslscan"

    def command(self, target: str) -> list[str]:
        """sslscan --no-colour --xml=- <target> — XML to stdout."""
        return ["sslscan", "--no-colour", "--xml=-", target]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse sslscan XML <ssltest><cipher> with status enabled → Host facts."""
        written: list[str] = []
        host_addr = _host_of(target)
        protocols: list[str] = []
        ciphers: list[str] = []
        text = raw_output.strip()
        if not text:
            return ()
        # XML path first if it looks like XML
        if text.lstrip().startswith("<?xml") or "<ssltest" in text or "<cipher" in text:
            try:
                root = fromstring(raw_output)
                for cipher_el in root.findall(".//cipher"):
                    status = cipher_el.get("status", "")
                    if status.lower() not in ("accepted", "enabled", "ok", "yes"):
                        # sslscan marks enabled ciphers; keep only enabled
                        continue
                    cipher_name = (
                        cipher_el.get("cipher")
                        or cipher_el.get("name")
                        or (cipher_el.text or "").strip()
                    )
                    if cipher_name:
                        ciphers.append(cipher_name)
                    proto = cipher_el.get("sslversion") or cipher_el.get("protocol") or ""
                    if proto:
                        protocols.append(proto)
                for proto_el in root.findall(".//protocol"):
                    if proto_el.get("enabled", "").lower() in ("yes", "true", "1", "enabled"):
                        name = proto_el.get("type") or proto_el.text or ""
                        if name:
                            protocols.append(str(name).strip())
            except Exception:  # noqa: BLE001, S110 — XML parse best-effort, fall back to regex
                pass
        # Fallback regex for enabled ciphers/protocols in raw text
        if not protocols and not ciphers:
            for m in re.finditer(
                r"(TLSv?1[._][012]|SSLv?3)[^\n]*enabled", raw_output, re.IGNORECASE
            ):
                protocols.append(m.group(1))
            for m in re.finditer(r"Accepted\s+([A-Z0-9\-_]+)", raw_output):
                ciphers.append(m.group(1))
        node = _tls_facts_to_host(self.graph, host_addr, protocols, ciphers, self.name)
        written.append(node)
        return tuple(written)


# ---------------------------------------------------------------------------
# sslyze
# ---------------------------------------------------------------------------


class SslyzeRunner(ReconToolRunner):
    """Emit TLS Host facts from sslyze JSON (§9). Facts only."""

    name = "sslyze"
    binary = "sslyze"

    def command(self, target: str) -> list[str]:
        """sslyze --json_file - <target> — JSON scan results to stdout."""
        return ["sslyze", "--json_file", "-", target]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse sslyze JSON server_scan_results into Host facts."""
        written: list[str] = []
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return ()
        results = (
            parsed.get("server_scan_results", [parsed]) if isinstance(parsed, dict) else parsed
        )
        if not isinstance(results, list):
            results = [results]
        for entry in results:
            if not isinstance(entry, dict):
                continue
            scan = entry.get("scan_result", entry)
            if not isinstance(scan, dict):
                continue
            protocols: list[str] = []
            ciphers: list[str] = []
            # sslyze nests under ssl_2_0_cipher_suites, ssl_3_0_cipher_suites, tls_1_0/1_1/1_2/1_3
            for key in (
                "ssl_2_0_cipher_suites",
                "ssl_3_0_cipher_suites",
                "tls_1_0_cipher_suites",
                "tls_1_1_cipher_suites",
                "tls_1_2_cipher_suites",
                "tls_1_3_cipher_suites",
            ):
                suite = scan.get(key)
                if isinstance(suite, dict) and suite.get("accepted_cipher_suites"):
                    proto = key.replace("_cipher_suites", "").upper()
                    protocols.append(proto)
                    for cipher in suite["accepted_cipher_suites"]:
                        if isinstance(cipher, dict) and cipher.get("name"):
                            ciphers.append(str(cipher["name"]))
                        elif isinstance(cipher, str):
                            ciphers.append(cipher)
            # Also check scan_commands_results shape
            scr = scan.get("scan_commands_results", {})
            if isinstance(scr, dict):
                for _k, v in scr.items():
                    if isinstance(v, dict) and "accepted_cipher_suites" in v:
                        for cipher in v.get("accepted_cipher_suites", []):
                            name = cipher.get("name") if isinstance(cipher, dict) else str(cipher)
                            ciphers.append(str(name))
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and item.get("cipher"):
                                ciphers.append(str(item["cipher"]))
            host_addr = _host_of(
                str(entry.get("server_location", {}).get("hostname", target))
                if isinstance(entry.get("server_location"), dict)
                else target
            )
            node = _tls_facts_to_host(self.graph, host_addr, protocols, ciphers, self.name)
            if node not in written:
                written.append(node)
        if not written:
            # Fallback if JSON shape not matched but raw had TLS tokens
            protocols = re.findall(r"TLSv?1[._][0123]|SSLv?3", raw_output)
            if protocols:
                host_addr = _host_of(target)
                node = _tls_facts_to_host(self.graph, host_addr, protocols, [], self.name)
                written.append(node)
        return tuple(written)
