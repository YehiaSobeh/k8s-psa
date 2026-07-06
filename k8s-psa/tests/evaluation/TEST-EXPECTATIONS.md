# k8s-psa Evaluation: Test Cases and Expected Results

## Test Environment
- **Cluster:** Minikube v1.35.0 on Ubuntu 22.04
- **Kubernetes:** v1.32.0
- **Container Runtime:** Docker 27.4.1 (Docker driver)
- **Scanner interval:** 60 seconds

## Overview of Test Cases

| Pod | Name | Purpose | L1 Violations | L2 Critical | L2 Warning | L2 Info |
|-----|------|---------|:---:|:---:|:---:|:---:|
| 1 | test-1-fully-hardened | Baseline: zero false positives | 0 | 0 | 0 | 0 |
| 2 | test-2-no-security | No securityContext at all | 2-3 | 0 | 0 | 0-1 |
| 3 | test-3-privileged-seccomp | **KEY: seccomp stripped by Docker** | 1 | **1** | **~27** | 0-1 |
| 4 | test-4-privileged-no-seccomp | Control for Test 3 | 3-4 | 0 | ~27 | 0-1 |
| 5 | test-5-partial-security | Partial cap drops | 1 | 0 | 0 | 0-1 |
| 6 | test-6-no-privesc | allowPrivilegeEscalation=false | 0 | 0-1 | 0 | 0 |
| 7 | test-7-host-namespaces | Host PID/Network/IPC | 5-6 | 0 | 0 | 1-3 |

---

## Detailed Test Case Descriptions

### Test 1: Fully Hardened Baseline

**What is configured:**
```yaml
securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
```

**What Docker will do:**
- Set UID=1000, GID=1000
- Drop all Linux capabilities (effective set = empty)
- Apply seccomp filter (SecurityOpt includes seccomp profile)
- Set ReadonlyRootfs=true
- Set no-new-privileges flag
- Use isolated namespaces (PidMode="", NetworkMode=pod, IpcMode="")

**Why no drift is expected:**
Every declared restriction is faithfully enforced by Docker for non-privileged containers. The spec and runtime agree on all 7 fields.

**This pod proves:** The tool has a 0% false positive rate on compliant workloads.

---

### Test 2: No Security Context

**What is configured:**
```yaml
containers:
- name: bare-app
  image: busybox:latest
  command: ["sleep", "3600"]
  # No securityContext
```

**What Docker will do:**
- Run as root (UID=0, from image default)
- Grant 14 default Linux capabilities
- No seccomp filter
- Writable root filesystem
- No noNewPrivileges flag
- Isolated namespaces

**Why no drift is expected:**
The spec declares nothing, so the drift detector has nothing to compare against. The "expected" capability set equals the defaults, and the runtime grants exactly the defaults. There is no mismatch between intent and enforcement — there simply is no declared intent.

**Layer 1 catches this:** The policy engine flags missing seccomp and writable rootfs because the spec does not meet the security baseline.

**This pod proves:** Layer 1 and Layer 2 are complementary. Layer 1 catches missing declarations. Layer 2 catches broken enforcement. A pod with no declarations has no enforcement to verify.

---

### Test 3: Privileged + Seccomp Declared (THE KEY SCENARIO)

**What is configured:**
```yaml
securityContext:
  privileged: true
seccompProfile:
  type: RuntimeDefault    # <-- THIS IS THE TRAP
```

**What Docker will do:**
- Privileged=true in Docker means:
  - Grant ALL 41 Linux capabilities (not just the 14 defaults)
  - **STRIP the seccomp filter entirely** (even though the spec declares RuntimeDefault)
  - Remove all masked /proc paths (/proc/kcore, /proc/keys, etc.)
  - Remove all readonly /proc paths
  - Grant full device access

**Why CRITICAL drift is expected:**
The Kubernetes pod spec says "apply RuntimeDefault seccomp profile" but Docker's privileged mode overrides this and runs the container with NO seccomp filter. Any tool that only reads the Kubernetes API (Gatekeeper, Kyverno, Kubescape, Trivy) would see "seccomp: RuntimeDefault" and report the container as having syscall filtering. Only by querying `docker inspect` does the truth emerge: the container runs unconfined.

**Expected drift findings:**
1. `seccompProfile` → CRITICAL: declared RuntimeDefault, actual is unconfined
2. `capabilities` → 27x WARNING: each non-default capability (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, etc.) is present at runtime but was not explicitly requested in the spec

**This pod proves:** The enforcement verification gap is real. Docker silently strips declared security restrictions for privileged containers. This is documented in containerd issue #7190 and Kubernetes issue #75559 but no existing tool detects it at runtime.

---

### Test 4: Privileged Without Seccomp (Control Case)

**What is configured:**
```yaml
securityContext:
  privileged: true
  runAsUser: 0
# No seccomp declared
```

**What Docker will do:**
- Same as Test 3 (all caps, no seccomp, no masks) — but this time the spec ALSO does not declare seccomp.

**Why no CRITICAL drift is expected:**
Both spec and runtime agree: no seccomp. The drift detector sees spec_type="" (empty) and runtime has no seccomp → both unconfined → no mismatch.

**Comparison with Test 3:**
This is the scientific control. Same privileged container, but without the seccomp declaration. Test 3 produces 1 CRITICAL (seccomp stripped). Test 4 produces 0 CRITICAL (seccomp never declared). The difference between the two tests isolates exactly one variable: whether seccomp was declared.

| | Test 3 | Test 4 |
|---|---|---|
| privileged | true | true |
| seccomp declared | RuntimeDefault | none |
| Runtime seccomp | unconfined | unconfined |
| L2 CRITICAL | **1 (seccomp mismatch)** | **0** |
| L2 WARNING | ~27 (caps) | ~27 (caps) |

**This pod proves:** The drift detector correctly distinguishes between "restriction declared but not enforced" (CRITICAL) and "restriction never declared" (no finding).

---

### Test 5: Partial Security Hardening

**What is configured:**
```yaml
securityContext:
  runAsUser: 1000
  readOnlyRootFilesystem: false     # Deliberately not hardened
  capabilities:
    drop: ["NET_RAW", "SYS_ADMIN"]  # Drop 2 specific caps, keep rest
seccompProfile:
  type: RuntimeDefault
```

**What Docker will do:**
- UID=1000
- Capabilities = 14 defaults - NET_RAW - SYS_ADMIN = 12 capabilities
- Seccomp applied
- Writable rootfs
- Isolated namespaces

**Why no drift is expected:**
The normalizer computes: expected = DEFAULT_CAPABILITIES - {NET_RAW, SYS_ADMIN} = 12 caps. Docker grants exactly those 12. The spec says rootfs is writable and runtime agrees. Everything matches.

**This pod proves:** The normalizer correctly handles partial capability drops. It does not produce false positives for non-ALL drop lists.

---

### Test 6: Privilege Escalation Control

**What is configured:**
```yaml
securityContext:
  allowPrivilegeEscalation: false   # Maps to noNewPrivileges=true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
```

**What Docker should do:**
- Add "no-new-privileges" to SecurityOpt
- This prevents SUID binaries from escalating privileges

**What might happen:**
- If Docker correctly translates allowPrivilegeEscalation=false → noNewPrivileges=true → **0 findings** (match)
- If Docker does NOT set the flag → **1 CRITICAL** finding (privilege escalation not blocked)

**This pod proves:** Whether the Kubernetes-to-Docker translation of allowPrivilegeEscalation is faithful on Minikube. Either result is valuable for the thesis: a match confirms enforcement, a mismatch discovers another gap.

---

### Test 7: Host Namespace Access

**What is configured:**
```yaml
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - securityContext:
      capabilities:
        add: ["SYS_ADMIN"]
```

**What Docker will do:**
- K8s implements hostNetwork through CNI, not Docker's --net=host
- Docker's NetworkMode may show the CNI network name, not "host"
- PidMode and IpcMode may or may not be "host"

**What the drift detector sees:**
- It reads Docker's PidMode, NetworkMode, IpcMode
- Maps "host" → ns=2 (host), anything else → ns=0 (isolated)
- Compares against spec's hostPID/hostNetwork/hostIPC

**Expected findings:**
From your previous data, pods with hostNetwork=true showed "isolated (mode=0)" at the Docker level. This produces INFO findings (spec says host but runtime shows isolated). This is not a security problem — the pod IS using host networking, but the implementation path differs from Docker's native mechanism.

**This pod proves:** How Kubernetes host namespace declarations map (or don't map) to Docker's namespace modes. The drift detector documents this translation gap.

---

## How to Run the Evaluation

```bash
cd ~/diploma/k8s-psa

# Deploy all test pods and collect results
bash tests/evaluation/run-evaluation.sh

# Generate the visual dashboard from results
python3 analyze.py evaluation_results_*.log evaluation_dashboard.html
xdg-open evaluation_dashboard.html
```

## What to Write in the Thesis Evaluation Chapter

### Detection Accuracy Table

After running, fill in actual values:

| Pod | Expected L2 Critical | Actual L2 Critical | Expected L2 Warning | Actual L2 Warning | Match? |
|-----|:---:|:---:|:---:|:---:|:---:|
| 1-fully-hardened | 0 | ___ | 0 | ___ | ___ |
| 2-no-security | 0 | ___ | 0 | ___ | ___ |
| 3-privileged-seccomp | 1 | ___ | ~27 | ___ | ___ |
| 4-privileged-no-seccomp | 0 | ___ | ~27 | ___ | ___ |
| 5-partial-security | 0 | ___ | 0 | ___ | ___ |
| 6-no-privesc | 0-1 | ___ | 0 | ___ | ___ |
| 7-host-namespaces | 0 | ___ | 0 | ___ | ___ |

### Key Metrics to Report

1. **True Positive Rate:** How many of the known drift scenarios (Test 3 seccomp) were detected?
2. **False Positive Rate:** How many compliant pods (Test 1) produced critical or warning findings?
3. **Detection Latency:** Time from pod creation to first drift finding (should be ≤ scan interval)
4. **Coverage:** How many of the 7 securityContext fields produce correct results?

### The Thesis Argument

Test 3 vs Test 4 is the centerpiece of the evaluation. Both are privileged containers. Both have all capabilities at runtime. Both run without seccomp at runtime. But ONLY Test 3 has a seccomp declaration in the spec. ONLY Test 3 produces a CRITICAL drift finding.

This proves that:
1. Docker silently strips declared seccomp profiles from privileged containers
2. No existing spec-only tool would detect this (they see "RuntimeDefault" and stop)
3. Only by comparing spec vs runtime state can this enforcement gap be discovered
4. The k8s-psa drift detector correctly identifies this specific divergence
