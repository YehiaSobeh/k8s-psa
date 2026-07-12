# k8s-psa — Kubernetes Pod Security Auditor

**k8s-psa** detects the *enforcement verification gap* in Kubernetes: the blind spot between what a pod's `securityContext` **declares** and what the container runtime **actually enforces**. Every existing policy tool (OPA Gatekeeper, Kyverno, Pod Security Admission) reads only the declared specification from the Kubernetes API; none of them verifies that the runtime translated those declarations into kernel-level enforcement. k8s-psa does.

> Not to be confused with Kubernetes' built-in **Pod Security Admission (PSA)** controller, which validates declared manifests at admission time only.

## Key findings made with this tool

1. **Enforcement gap (CRITICAL):** privileged containers that declare `seccompProfile.type: RuntimeDefault` have that seccomp filter **silently stripped** by the Docker runtime. Every specification-only tool reports these containers as filtered; they are not.
2. **Observability gap:** for correctly protected non-privileged containers, Docker's metadata (`docker inspect`) shows an empty `SecurityOpt` — indistinguishable from an unprotected container (CIS Docker Benchmark check 5.21). Runtime metadata is a lossy abstraction over kernel state.

## How it works

k8s-psa runs as a **DaemonSet** (one scanner per node) and performs a two-layer scan every 60 s (configurable):

| Layer | Source | Detects |
|-------|--------|---------|
| **Layer 1 — Spec Check** | Kubernetes API | Missing/weak security declarations (8 configurable policies) |
| **Layer 2 — Drift Detection** | Kubernetes API **vs.** container runtime (`docker inspect` / `crictl inspect`) | Declared restrictions absent at runtime (**CRITICAL**), undeclared capabilities present (**WARNING**), runtime stricter than declared (**INFO**) |

A capability normalizer computes the *expected* runtime capability set (14 runtime defaults ± `add`/`drop` lists) so that only genuine deviations produce findings. Results are written as NDJSON and served by a real-time dashboard (Chart.js, port 8080).

```
src/
├── main.py               # orchestrator / DaemonSet entry point
├── pod_scanner.py        # Kubernetes API retrieval
├── spec_extractor.py     # pod spec → SpecSecurityState
├── runtime_inspector.py  # docker/crictl → RuntimeSecurityState
├── policy_engine.py      # Layer 1 checks
├── normalizer.py         # expected-capability computation
├── drift_detector.py     # Layer 2 field-by-field comparison
├── alert_manager.py      # NDJSON serialisation
└── models.py             # dataclasses
```

## Quickstart (Minikube)

```bash
minikube start
bash deploy.sh                                # build images, load, deploy scanner + dashboard
bash tests/evaluation/run-evaluation.sh       # deploy the 7 evaluation pods
kubectl port-forward svc/k8s-psa-dashboard 8080:8080 -n k8s-psa-system
# open http://localhost:8080
```

## Evaluation

`tests/evaluation/` contains 7 purpose-built pods covering the security spectrum (fully hardened → privileged → host namespaces), with `TEST-EXPECTATIONS.md` documenting the expected finding for each. The controlled pair **pod-3** (privileged + seccomp declared) vs **pod-4** (privileged, no seccomp) isolates the seccomp declaration as the single variable and demonstrates the detector's specificity.

```bash
python -m pytest tests/          # 44 unit tests, ~0.2 s
```

Measured footprint: ~3.1 s per scan cycle (16 pods), 64 MiB RAM, <100m CPU.

## Requirements

- Kubernetes ≥ 1.25 (evaluated on v1.32.0, Minikube v1.35.0)
- Docker or containerd runtime socket mounted on the node
- Python 3.10+, `pyyaml`, `kubernetes` (see `requirements.txt`)

## Citation

If you use k8s-psa in academic work, please cite the paper (see `CITATION.cff`):

> Y. Sobeh, "Bridging the Enforcement Verification Gap: Detecting Divergence Between Declared and Actual Security Posture in Kubernetes Containerized Environments," 2026.

## License

MIT — see [LICENSE](LICENSE).
