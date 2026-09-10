---
name: grafana-prometheus
category: vulnerability
description: Grafana/Prometheus-specific attack surface — unauthenticated metrics/API exposure, data-source proxy SSRF, dashboard-injection, and a per-class proof ladder
keywords: [grafana, prometheus, observability, metrics, alertmanager, data source proxy]
---

# Grafana / Prometheus

Observability stacks are frequently deployed with weaker access control
than the application they monitor, on the assumption that "it's just
metrics" — in practice, metrics and dashboards routinely leak internal
topology, business data, and outright secrets, and Grafana's data-source
proxy is a real SSRF primitive.

## Attack Surface

- Prometheus's own `/metrics`, `/api/v1/query`, and `/api/v1/label/.../values`
  endpoints, and Alertmanager's API — commonly deployed with no
  authentication at all, reachable internally or occasionally externally.
- Grafana's data-source proxy (`/api/datasources/proxy/:id/...`) —
  forwards a request to the configured backend (Prometheus, InfluxDB,
  Elasticsearch, a cloud provider's monitoring API) using the
  data source's OWN stored credentials; if the proxy path or query is
  insufficiently restricted, this is a direct SSRF primitive against
  whatever internal network the Grafana server itself can reach.
- Grafana's default/weak admin credentials (`admin`/`admin` unchanged),
  and public dashboard sharing (`Share > Public dashboard`) potentially
  exposing an internal metric set to unauthenticated external viewers.
- Alert notification channel configuration (webhook URLs, Slack/email
  credentials) visible to any user with dashboard-editing rights, not
  just admins, in some role configurations.

## Recon

- Probe for unauthenticated Prometheus/Alertmanager endpoints directly —
  `/metrics`, `/api/v1/query?query=up`, `/api/v1/status/config` (the
  latter can disclose scrape target internals, occasionally credentials
  embedded in scrape configs).
- Enumerate configured data sources in Grafana (via the UI/API if
  authenticated at any level) and identify which ones proxy to an
  internal-only backend — this is the SSRF-relevant subset.
- Check the Grafana version against known default-credential and
  public-dashboard-related advisories for that specific version.

## Techniques

1. **Unauthenticated Prometheus/Alertmanager data exposure**, direct
   probing per Recon — confirm what business/internal data the exposed
   metrics actually reveal (customer counts, internal hostnames, request
   patterns by endpoint) beyond generic system metrics.
2. **Data-source proxy SSRF.** Via an authenticated (even low-privilege)
   Grafana session, attempt to manipulate the proxied query/path to
   reach an internal host/port the data source's own configured backend
   wouldn't normally serve — confirmed via a benign, observable response
   difference or an OAST callback, applying [[ssrf]]'s own methodology
   through this specific proxy mechanism.
3. **Default-credential and public-dashboard check.** Attempt the
   well-known default admin credentials directly; separately, enumerate
   any dashboards shared via the public-link feature and assess what
   they expose to an unauthenticated viewer.

## Proof Ladder

Follow [[ssrf]]'s own proof ladder for the data-source-proxy primitive;
an unauthenticated data-exposure finding follows
[[information-disclosure]]'s ladder.

## Validation and False-Positive Discipline

Apply [[closure-discipline]]. Metrics endpoints confirmed to require
authentication (a 401/403 on direct probe) close this specific exposure
path. A data-source proxy confirmed to restrict the proxied request to
only the specific query shape the dashboard needs (not an arbitrary
path/host) closes the SSRF primitive for that data source.

## Impact

Internal topology and business-data disclosure via unauthenticated
metrics endpoints; SSRF against internal infrastructure via the data-
source proxy, using that data source's own stored, often privileged
credentials; full Grafana compromise via default credentials.

## Summary

Always probe for unauthenticated metrics/Alertmanager access directly —
this is commonly deployed with weaker access control than the primary
application. Separately, the data-source proxy is a genuine SSRF
primitive worth testing on its own, not just an internal implementation
detail.
