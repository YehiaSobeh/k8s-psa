# k8s-psa — Kubernetes Pod Security Auditor

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue) ![Kubernetes 1.25+](https://img.shields.io/badge/kubernetes-1.25%2B-326ce5) ![Tests](https://img.shields.io/badge/tests-44%20passing-brightgreen)

**Demo video:** https://youtu.be/SyWH9YpJL2Y

> Status: Bachelor's thesis at Innopolis University, defended June 2026 (supervisor: Prof. Kirill Saltanov). Conference paper in preparation.


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

![k8s-psa dashboard](docs/dashboard.png)
*[ADD SCREENSHOT: docs/dashboard.png, the live dashboard showing Layer 1 and Layer 2 findings for the 7 evaluation pods]*

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

### Cross-runtime validation (containerd)

The two findings were replicated on containerd 1.7.24 with kernel-level ground truth (`/proc/<pid>/status`). The enforcement gap generalizes: containerd also strips the declared seccomp profile from privileged containers (`Seccomp: 0`). The observability gap is Docker-specific: `crictl inspect` on containerd exposes the full OCI seccomp config. Raw evidence and procedure: [`tests/evaluation/containerd-validation/`](tests/evaluation/containerd-validation/RESULTS.md).

## Repository layout

```
src/                      scanner (see module list above)
dashboard/                Flask + Chart.js live dashboard
deployments/all-in-one.yaml   namespace, RBAC, ConfigMap, DaemonSet, dashboard Service
policies/default.yaml     Layer 1 policy set (8 checks)
tests/                    44 unit tests, fixtures (docker/crictl inspect dumps), 7 evaluation pods, raw results
docs/                     screenshots
deploy.sh                 build images, load into Minikube, apply manifests
analyze.py                summarise evaluation NDJSON into tables
```

## What I learned

- Runtime metadata is not kernel state. `docker inspect` showing an empty `SecurityOpt` can mean "unprotected" or "protected by the implicit default"; only `/proc/<pid>/status` settles it. Building the detector taught me to treat every intermediate abstraction as potentially lossy.
- The strip decision happens in the container runtime, not the kubelet. Tracing the CRI request for Pod 3 and comparing it with the generated OCI spec was the moment the result became defensible.
- A controlled pair (Pod 3 vs Pod 4) that changes one variable is worth more than a large uncontrolled test set. Reviewers and supervisors both pointed at that experiment first.
- Honest limitations sections make the work stronger. The false positives of my own tool turned into the second contribution.

## Requirements

- Kubernetes ≥ 1.25 (evaluated on v1.32.0, Minikube v1.35.0)
- Docker or containerd runtime socket mounted on the node
- Python 3.10+, `pyyaml`, `kubernetes` (see `requirements.txt`)

## Citation

If you use k8s-psa in academic work, please cite the paper (see `CITATION.cff`):

> Y. Sobeh, "Bridging the Enforcement Verification Gap: Detecting Divergence Between Declared and Actual Security Posture in Kubernetes Containerized Environments," 2026.

## License

MIT — see [LICENSE](LICENSE).
