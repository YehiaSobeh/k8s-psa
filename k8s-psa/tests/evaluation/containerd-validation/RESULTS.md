# Cross-Runtime Validation: containerd (2026-07-12)

Targeted replication of the paper's two key findings on containerd instead of Docker.

## Environment

- Minikube profile `containerd-exp` (recreate: `minikube start -p containerd-exp --container-runtime=containerd --memory=2200mb --cpus=2 --driver=docker`)
- Kubernetes **v1.32.0** (identical to the Docker-runtime experiment), containerd **1.7.24**, runc **1.2.2**, Ubuntu 22.04
- Pods deployed: `pod-1-fully-hardened`, `pod-3-privileged-seccomp`, `pod-4-privileged-no-seccomp` (unchanged YAMLs)
- Evidence: `crictl-inspect-pod{1,3,4}.json` (full `crictl inspect` dumps), `proc-status.txt` (kernel ground truth), `environment.txt`

## Results

| Check | Pod 1 (hardened) | Pod 3 (priv + seccomp) | Pod 4 (priv, no seccomp) |
|---|---|---|---|
| OCI `runtimeSpec.linux.seccomp` | **PRESENT** (allowlist, defaultAction=SCMP_ACT_ERRNO) | **ABSENT** | **ABSENT** |
| OCI bounding capabilities | 0 | 41 | 41 |
| Kernel `/proc/1/status` Seccomp | **2** (BPF filter active) | **0** (none) | **0** (none) |
| Kernel CapBnd | `0000000000000000` | `000001ffffffffff` (41 bits) | `000001ffffffffff` (41 bits) |
| CRI `security_context.seccomp` passed by kubelet | RuntimeDefault (`{}` = protobuf default enum 0) | RuntimeDefault (`{}`) | — |

## Conclusions

1. **The enforcement gap generalizes beyond Docker.** Pod 3 declares `seccompProfile.type: RuntimeDefault`; the kubelet passes it through the CRI; **containerd strips it** for privileged containers (kernel Seccomp=0). The paper's central finding is not a Docker quirk — it holds on the runtime that dominates production.
2. **The strip decision is made by the container runtime, not the kubelet.** The CRI request for Pod 3 contains the seccomp profile (same as Pod 1); only the generated OCI spec differs. (Note: in the protobuf JSON dump, `seccomp: {}` means `profile_type: RuntimeDefault` — enum value 0 is omitted by JSON serialization. Naive inspection would misread this as "no profile"; yet another metadata-semantics trap.)
3. **The observability gap is Docker-specific and disappears on containerd.** `crictl inspect` exposes the full OCI runtime spec: Pod 1's seccomp allowlist is explicitly visible, matching kernel state (Seccomp=2). The false positives the paper reported for Docker would not occur on containerd — confirming the paper's Limitations hypothesis.
4. **Kernel-level verification (`/proc/<pid>/status`) worked as ground truth**, prototyping the paper's first future-work item.

## Cleanup

`minikube delete -p containerd-exp` (the default `minikube` profile was never touched).
