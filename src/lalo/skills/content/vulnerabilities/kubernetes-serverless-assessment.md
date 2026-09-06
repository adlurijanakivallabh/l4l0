---
name: kubernetes-serverless-assessment
category: vulnerability
description: Kubernetes and serverless platform assessment — exposed control planes, over-permissive RBAC and service-account scope, container escape, registry exposure, with a per-class proof ladder
keywords: [kubernetes, k8s, serverless, lambda, rbac, service account, container escape, kubelet, etcd, container registry]
---

# Kubernetes and Serverless Assessment

Container-orchestration and serverless platforms move the trust boundary
from "the host" to "the control plane" — a leaked service-account token,
an exposed kubelet API, or a broad execution role does the same job a
leaked root password would on a traditional host. Most real findings here
come from inherited scope (what a token or role turns out to actually
grant) being wider than whoever configured it intended.

## Attack Surface

- An exposed Kubernetes API server accepting anonymous or weakly
  authenticated requests, or a default service-account token mounted into
  a pod granting more than that pod's own workload needs.
- Overly broad RBAC bindings — a `ClusterRoleBinding` granting
  cluster-admin-equivalent verbs/resources to a role wider than the
  operators who set it up realized.
- Exposed node-level or cluster-state surfaces: the kubelet API
  (unauthenticated on its read-only port in older/misconfigured clusters),
  an unauthenticated etcd instance, or a reachable Kubernetes Dashboard.
- Container escape vectors reachable from an already-obtained pod shell:
  privileged containers, `hostPath` mounts into sensitive host
  directories, `hostNetwork`/`hostPID`, or a missing seccomp/AppArmor
  profile.
- Serverless-specific: function URLs or API-gateway routes with no
  authentication, an execution role broader than the function's own code
  requires, or secrets injected as plaintext environment variables
  disclosed via a code-execution or information-disclosure bug in the
  function itself.
- Container registries accepting anonymous pull or, more seriously,
  anonymous push — the latter is a supply-chain compromise vector, not
  just an information leak.

## Recon

- Fingerprint the orchestration platform from response headers, error
  pages, and DNS/service-naming patterns before assuming which control
  surfaces are even present.
- Probe for the well-known unauthenticated-by-default surfaces directly:
  the kubelet API ports, an exposed etcd port, and any dashboard reachable
  without a login redirect.
- If any pod-level shell access already exists (from an application-level
  RCE elsewhere in the engagement), the mounted service-account token is
  the very next thing to check — read it, then confirm its *actual*
  permissions via the cluster's own "can I" query rather than assuming
  from the pod's role.
- Enumerate serverless function endpoints from recon already covered by
  API-spec parsing (OpenAPI/API-gateway routes), then check which ones
  actually enforce authentication versus which merely appear to.
- For registries, attempt an anonymous manifest/catalog listing before
  anything else — many misconfigured registries disclose their full image
  inventory with no credentials.

## Techniques (start quiet, escalate only as needed)

1. **Unauthenticated surface checks first.** Kubelet, etcd, dashboard, and
   registry anonymous-access checks all need zero credentials and often
   reach a reportable finding on their own.
2. **Service-account scope confirmation.** From any obtained token, query
   the cluster's own permission-check API for the *specific* actions you
   are about to test — never assume cluster-admin from a role name or a
   broad-sounding binding.
3. **Container escape, only from a legitimate pod shell.** Check for
   privileged mode, `hostPath`, and `hostPID`/`hostNetwork` before
   attempting anything — prefer the least invasive escape that proves node
   access (reading a node-only file) over a heavier kernel-level exploit
   chain, and only escalate further if the engagement's scope and time
   budget call for it.
4. **Lateral movement via internal service discovery.** Once any in-cluster
   network position exists, internal DNS enumeration
   (`*.svc.cluster.local`) and unauthenticated internal APIs are the
   natural next targets — the same "assume nothing is protected until
   proven" discipline as any internal network segment.
5. **Serverless-specific escalation.** Test function-URL authentication
   bypass directly, and — if code execution in the function is achieved —
   confirm the actual scope of its execution role and check for injected
   secrets in the environment, the same identity-confirmation-first
   discipline as [[cloud-iam-storage-misconfiguration]].
6. **Registry write testing, carefully.** Confirm write access with a
   single benign, clearly-labeled test image and a tag that cannot be
   mistaken for a real deployment — never push to a tag any real workload
   might pull, and never overwrite an existing image.

## Proof Ladder

- **L1 — exposed surface identified.** An unauthenticated-reachable
  control-plane or registry surface is confirmed to exist, but no data or
  access has been obtained from it yet.
- **L2 — low-privilege access or metadata obtained.** Cluster or registry
  metadata was read without authorization, or a low-scope token was
  obtained and its identity confirmed.
- **L3 — meaningful cluster access confirmed.** Namespace-scoped
  resource read/write, pod exec, a confirmed container-escape primitive,
  or confirmed anonymous registry write access. This is the threshold for
  a reportable finding.
- **L4 — node, cluster, or supply-chain compromise.** Full node
  compromise via container escape, cluster-admin-equivalent access
  obtained, cross-tenant access in a multi-tenant cluster, or a
  demonstrated supply-chain compromise path via a writable registry.

Calibrate severity separately per [[severity-calibration]] — a
namespace-scoped read of a non-sensitive ConfigMap is a different severity
from cluster-admin access or a writable production registry, even though
both can clear L3.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- A broad RBAC binding that intentionally grants a legitimate operator
  service (a CI/CD controller, an autoscaler) wide permissions is not
  automatically a finding — confirm the binding is actually reachable by
  something *other* than its intended operator before reporting it.
- A pod shell obtained via application RCE inherits exactly that pod's own
  service-account scope, nothing more — confirm the specific token's
  actual permissions rather than assuming broader cluster access from the
  application's own apparent importance.
- A resource visible across namespaces may be an intentionally shared
  ConfigMap or Secret, not evidence of a namespace-isolation failure —
  confirm the specific resource's sensitivity before recording a boundary
  violation.
- Confirm you are testing the actual deployed cluster, not a local
  development or CI-ephemeral cluster with intentionally relaxed defaults
  that never reaches production.

## Impact

Node or full cluster compromise, lateral movement across tenant
boundaries in multi-tenant environments, supply-chain compromise via a
writable container registry, and bulk secrets exfiltration from
cluster-wide or organization-wide credential stores.

## Summary

Kubernetes and serverless assessment chains exposed control-plane surfaces
and inherited service-account or execution-role scope into cluster-wide
compromise. Always confirm the exact scope of any token or role you obtain
via the platform's own permission-check API — never assume it from a
binding's name or a pod's apparent role.
