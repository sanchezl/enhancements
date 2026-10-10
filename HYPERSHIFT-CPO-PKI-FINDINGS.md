# HyperShift Control-Plane-Operator (CPO) PKI — Findings

**Scope:** How the HyperShift control-plane-operator generates/manages TLS certificates for a hosted control plane, how it differs from standalone OpenShift cert-generating operators, its configuration surface today, and implications for the Configurable PKI enhancement (openshift/enhancements#2115).

**Source:** Code review performed by Chai (Opus 4.6) against `github.com/openshift/hypershift`, `main` branch, pinned at commit `b36dd9034f72132b26818300903b13813b74d960` (`b36dd90`). Date: 2026-10-09.

---

## TL;DR

- **HyperShift uses its OWN cert-generation code**, not `library-go/pkg/crypto`. The initial hypothesis (same code, different config) is inverted: it is a separate implementation with **hardcoded** key/lifetime parameters.
- **Cert key size and lifetime are NOT configurable**: fixed RSA-2048 keys, 10-year CAs, 1-year leaves. The only knob is the `CERTIFICATE_VALIDITY` env var, which overrides *leaf* lifetime only.
- **HyperShift DOES honor a cluster TLS security profile** (`TLSSecurityProfile`) for component cipher-suite / TLS-version policy — but only for the serving/TLS config of components (e.g. KAS), **not** for cert key size or lifetime.
- The **configurable-PKI gap for HyperShift is specifically cert key-params / lifetime / signer config**, not TLS cipher policy.

---

## 1. Generation code — HyperShift's own, not library-go

For CPO-generated hosted-control-plane CAs and leaf certificates, HyperShift uses **`github.com/openshift/hypershift/support/certs`**, **not** `github.com/openshift/library-go/pkg/crypto` (the package standalone OpenShift operators such as cluster-kube-apiserver-operator and service-ca-operator use).

- Implementation: `support/certs/tls.go` — `GenerateSelfSignedCertificate()` and `GenerateSignedCertificate()` call Go's stdlib `crypto/rsa` and `crypto/x509` directly.
- CPO callers (in `control-plane-operator/controllers/hostedcontrolplane/pki/`):
  - `ca.go` — `reconcileSelfSignedCA()` → `certs.ReconcileSelfSignedCA()`
  - `cert.go` — `reconcileSignedCertWithKeysAndAddresses()` → `certs.ReconcileSignedCert()`

> Note: `library-go/pkg/crypto` *is* vendored in the repo and appears in TLS-profile helper usage, but it is not the path used for CPO cert generation.

---

## 2. Certificate parameters — hardcoded constants

All in `support/certs/tls.go` (lines ~29–35):

```go
keySize = 2048

ValidityOneDay   = 24 * time.Hour
ValidityOneYear  = 365 * ValidityOneDay
ValidityTenYears = 10 * ValidityOneYear
```

- **Key: RSA-2048, fixed.** `PrivateKey()` (≈ line 117–125 / used at line 119) calls `rsa.GenerateKey(Reader(), keySize)`. No ECDSA. `keySize` is defined once (line 30) and referenced once (line 119) — **no override anywhere**.
- **CAs: 10-year validity** (`ValidityTenYears`) — set in `ReconcileSelfSignedCA()` (≈ lines 469–480).
- **Leaf certs: 1-year default** (`ValidityOneYear`) — `ReconcileSignedCert()` (≈ lines 403–420). This is the **only** cert param with an override: the `CERTIFICATE_VALIDITY` env var (`CertificateValidityEnvVar`, line 54), parsed via `time.ParseDuration`.
- **Actual expiry:** `SelfSignedCertificate()` and `signedCertificate()` set `NotAfter: now.Add(cfg.Validity)` with `now := time.Now()`.

**vs standalone OpenShift:** standalone operators generate certs via `library-go/pkg/crypto` with their own rotation controllers and defaults (typically shorter, actively-rotated windows). HyperShift bakes in 10-year CAs / 1-year leaves as constants, so the two topologies are **not guaranteed to match** on key size or lifetime.

---

## 3. Hosted control-plane cert inventory

All reconcilers live in `control-plane-operator/controllers/hostedcontrolplane/pki/`, one file per cert family. Secret **names** are inline string literals built by `manifests` constructor functions in `control-plane-operator/controllers/hostedcontrolplane/manifests/pki.go` (no shared name-constant package).

### Core override-relevant certs (name → standalone role)

| HyperShift secret name | `pki.go` constructor (line) | Standalone role it maps to |
|---|---|---|
| `kas-aggregator-crt` | `KASAggregatorCertSecret` (219) | aggregator / front-proxy **client** cert |
| `kas-aggregator-client-signer` | `AggregatorClientSigner` (215) | front-proxy / aggregator signer CA |
| `sa-signing-key` | `ServiceAccountSigningKeySecret` (269) | service-account signing key |
| `system-admin-signer` | `SystemAdminSigner` (237) | admin-kubeconfig / `system:admin` signer CA |
| `kas-server-crt` | `KASServerCertSecret` (203) | kube-apiserver serving cert |
| `etcd-server-tls` | `EtcdServerSecret` (179) | etcd server cert |
| `etcd-peer-tls` | `EtcdPeerSecret` (183) | etcd peer cert |
| `kas-kubelet-client-crt` | `KASKubeletClientCertSecret` (211) | KAS → kubelet client cert |
| `kube-control-plane-signer` | `KubeControlPlaneSigner` (221) | kube-control-plane signer CA (KCM/scheduler/etc. client signer) |

These certs live in the **HCP (management-cluster) namespace** — a different trust/ownership boundary than standalone in-cluster secrets.

### Full file → cert-family map (pki/ package)

**Core control-plane CAs & certs:**
- `ca.go` — signer CAs: aggregator-client, kube-control-plane, KAS-to-kubelet, admin-kubeconfig, HCCO, KAS-bootstrap, kube-CSR, etcd, etcd-metrics; plus client-CA bundles, root CA/bundle, konnectivity bundle.
- `kas.go` — KAS server/private certs + client certs (kubelet, machine-bootstrap, aggregator, scheduler, KCM, `system:admin`, HCCO, bootstrap-container); SA & generic kubeconfigs.
- `etcd.go` — client, metrics-client, server, peer, shard-server, shard-peer.
- `konnectivity.go` — signers + server/cluster/client/agent certs.
- `kcm.go`, `scheduler.go` — KCM / scheduler server certs.
- `oauth.go` — OAuth server cert + OAuth master CA bundle.
- `openshift.go` — OpenShift APIServer, OAuth APIServer, authenticator, controller-manager certs.
- `sa.go` — service-account **signing key** secret + metrics SA client cert.

**Add-on / operator serving certs:**
`cvo.go`, `ingress.go`, `mcs.go`, `ignitionserver.go`, `nto.go`, `registryoperator.go`, `olm.go` (package server / catalog operator / OLM operator), `cluster_storage_operator.go`, `csi_snapshot_controller_operator.go`, `multus_admission_controller.go`, `network_node_identity.go`, `ovn_control_plane_metrics.go`, CSI driver/operator metrics certs (AWS EBS, Azure Disk/File, GCP PD), cloud workload-identity webhooks (AWS/Azure/GCP).

**Helpers (no cert family):** `cert.go`, `params.go`.

---

## 4. Configuration surface today

### Cert key size / lifetime / signer — NOT configurable
- `TLSSecurityProfile` / `tlsSecurityProfile` appears **nowhere** under `support/certs/` or the `pki/` package — it does not influence cert key size or lifetime.
- RSA key size is fixed at 2048 (no override).
- CA lifetime fixed at 10 years.
- Leaf lifetime: 1-year default, overridable **only** via the `CERTIFICATE_VALIDITY` env var.

### TLS cipher / version policy — IS configurable (via TLSSecurityProfile)
Repo-wide, `TLSSecurityProfile` is present (159 files) and **is honored** for component TLS policy through HyperShift's **v2 "control-plane-component" architecture**:

- KAS: `v2/kas/config.go` `generateConfig()` (line 180) → `ApplyServingInfoFromTLSProfile()` in `support/config/servinginfo.go` (lines 12–23), which sets `ServingInfo.MinTLSVersion` + `ServingInfo.CipherSuites`.
- Source of truth: `v2/kas/params.go` `NewConfigParams()` / `tlsSecurityProfile()` reads `hcp.Spec.Configuration.APIServer.TLSSecurityProfile`, defaulting to **Intermediate** when unset.
- Resolution: `support/config/cipher.go` — `MinTLSVersion()` / `CipherSuites()` resolve the built-in or `Custom` profile (cipher names converted to IANA names).
- Default (**Intermediate**), per `v2/kas/config_test.go` (lines 854–862):
  - `MinTLSVersion`: `VersionTLS12` (TLS 1.2 minimum)
  - `CipherSuites`:
    ```
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    ```
- `TLSSecurityProfile` is threaded through the broader v2 component tree (`v2/{kas,kcm,kube_scheduler,oapi,oauth,oauth_apiserver,ocm,...}`), with shared plumbing in `support/config` and `support/controlplane-component`.

---

## 5. Implications for the Configurable PKI enhancement

- HyperShift **already** honors a cluster TLS security profile (cipher-suite / TLS-version) for hosted control-plane components via `hcp.Spec.Configuration.APIServer.TLSSecurityProfile`. The enhancement does not need to introduce that for cipher/version.
- The actual gap: **no config surface for cert key size (fixed RSA-2048), cert lifetime (10yr CA / 1yr leaf), or signer behavior.** That is where HyperShift diverges from a configurable-PKI goal.
- **Naming recommendation (opinion):** use **HyperShift-specific names as the primary override key**, with a documented role-alias mapping to standalone well-known names — do *not* silently reuse standalone names. Rationale:
  - CPO's cert set is a superset/reshape of standalone (shard etcd, konnectivity signers, per-cloud webhooks) with no 1:1 name correspondence; reusing standalone names would be lossy/misleading.
  - CPO already has its own independent generation path and naming, so a standalone-keyed override would need a translation layer anyway.
  - Hosted certs live in the management-cluster namespace — a different trust/ownership boundary.
  - Where a CPO cert IS semantically the same as a standalone one (the 9 in the table above), define an explicit alias/role so a cluster-wide PKI policy can target "the same role" across both topologies.

---

## Open items / caveats (not verified)

- Whether the **v2 "control-plane-component" tree is the live/default path** vs the older `pki/` reconcilers was not exhaustively confirmed. The `TLSSecurityProfile` plumbing and KAS config generation clearly live in v2; the cert generation reviewed in sections 1–3 is the `pki/` + `support/certs` path. Confirming the v1-vs-v2 wiring would sharpen the EP.
- Line numbers are approximate where noted ("≈") and pinned to commit `b36dd90`; re-verify against current `main` before citing in the EP.
