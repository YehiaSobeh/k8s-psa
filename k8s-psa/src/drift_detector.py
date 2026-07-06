"""
Drift Detector — compares Kubernetes API security declarations against
the actual container runtime state.

This is the novel component of k8s-psa.  No existing open-source tool
performs this spec-vs-runtime comparison.

Each check method compares one security field and produces zero or more
DriftFinding objects classified by severity:

  CRITICAL  — a declared restriction is missing at runtime
  WARNING   — something is present at runtime that was not declared
  INFO      — a benign default added by the runtime (expected)
"""

import logging
from typing import List

from src.models import (
    SpecSecurityState,
    RuntimeSecurityState,
    DriftFinding,
    DriftReport,
    DriftSeverity,
    DriftCategory,
)
from src.normalizer import (
    compute_expected_capabilities,
    normalize_cap_name,
    DEFAULT_CAPABILITIES,
    is_default_capability,
)

logger = logging.getLogger(__name__)


class DriftDetector:
    """
    Compares a SpecSecurityState against a RuntimeSecurityState and
    produces a DriftReport listing every divergence.
    """

    def detect(
        self,
        spec: SpecSecurityState,
        runtime: RuntimeSecurityState,
    ) -> DriftReport:
        """
        Run all drift checks and return the consolidated report.
        """
        report = DriftReport(
            pod_name=spec.pod_name,
            namespace=spec.namespace,
            container_name=spec.container_name,
            container_id=runtime.container_id,
        )

        # Run each check and collect findings
        report.findings.extend(self._check_privileged(spec, runtime))
        report.findings.extend(self._check_user(spec, runtime))
        report.findings.extend(self._check_capabilities(spec, runtime))
        report.findings.extend(self._check_seccomp(spec, runtime))
        report.findings.extend(self._check_rootfs(spec, runtime))
        report.findings.extend(self._check_privilege_escalation(spec, runtime))
        report.findings.extend(self._check_namespaces(spec, runtime))

        return report

    # ── 1. Privileged mode ─────────────────────────────────────────

    def _check_privileged(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        spec_priv = spec.privileged
        runtime_priv = runtime.is_effectively_privileged

        if not spec_priv and runtime_priv:
            # CRITICAL: spec says non-privileged but runtime is privileged
            findings.append(DriftFinding(
                field_name="privileged",
                description=(
                    "Container is effectively privileged at runtime "
                    "(all capabilities, no seccomp, no masked paths) "
                    "but spec declares privileged=false"
                ),
                severity=DriftSeverity.CRITICAL,
                category=DriftCategory.PRIVILEGE_ESCALATION,
                declared_value="false",
                actual_value="true (inferred)",
            ))
        elif spec_priv and not runtime_priv:
            # INFO: spec says privileged but runtime is restricted
            # (unusual but not a security problem)
            findings.append(DriftFinding(
                field_name="privileged",
                description=(
                    "Spec declares privileged=true but runtime does "
                    "not appear fully privileged"
                ),
                severity=DriftSeverity.INFO,
                category=DriftCategory.BENIGN_DEFAULT,
                declared_value="true",
                actual_value="false (inferred)",
            ))

        return findings

    # ── 2. User / Group ID ─────────────────────────────────────────

    def _check_user(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        # Determine the effective declared UID
        # Container-level overrides pod-level
        declared_uid = spec.run_as_user
        if declared_uid is None:
            declared_uid = spec.pod_run_as_user

        actual_uid = runtime.uid

        if declared_uid is not None and actual_uid is not None:
            if declared_uid != actual_uid:
                # Determine severity: running as root when non-root
                # was declared is critical
                if declared_uid != 0 and actual_uid == 0:
                    severity = DriftSeverity.CRITICAL
                    category = DriftCategory.USER_MISMATCH
                    desc = (
                        f"Spec declares runAsUser={declared_uid} but "
                        f"container runs as UID 0 (root)"
                    )
                elif declared_uid == 0 and actual_uid != 0:
                    severity = DriftSeverity.INFO
                    category = DriftCategory.BENIGN_DEFAULT
                    desc = (
                        f"Spec declares runAsUser=0 but container "
                        f"runs as UID {actual_uid} (more restrictive)"
                    )
                else:
                    severity = DriftSeverity.WARNING
                    category = DriftCategory.USER_MISMATCH
                    desc = (
                        f"Spec declares runAsUser={declared_uid} but "
                        f"container runs as UID {actual_uid}"
                    )

                findings.append(DriftFinding(
                    field_name="runAsUser",
                    description=desc,
                    severity=severity,
                    category=category,
                    declared_value=str(declared_uid),
                    actual_value=str(actual_uid),
                ))

        # Check group
        declared_gid = spec.run_as_group
        if declared_gid is None:
            declared_gid = spec.pod_run_as_group

        if declared_gid is not None and runtime.gid is not None:
            if declared_gid != runtime.gid:
                findings.append(DriftFinding(
                    field_name="runAsGroup",
                    description=(
                        f"Spec declares runAsGroup={declared_gid} "
                        f"but container runs as GID {runtime.gid}"
                    ),
                    severity=DriftSeverity.WARNING,
                    category=DriftCategory.USER_MISMATCH,
                    declared_value=str(declared_gid),
                    actual_value=str(runtime.gid),
                ))

        return findings

    # ── 3. Capabilities ────────────────────────────────────────────

    def _check_capabilities(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        # Compute expected capability set from spec
        expected = compute_expected_capabilities(
            spec.capabilities_add, spec.capabilities_drop
        )

        # Use the bounding set as the runtime ground truth
        actual = set(runtime.capabilities_effective)
        if not actual:
            actual = set(runtime.capabilities_bounding)

        # ── Capabilities present at runtime but not expected ───────
        unexpected = actual - expected
        for cap in sorted(unexpected):
            if is_default_capability(cap):
                # Default cap not explicitly dropped — benign
                severity = DriftSeverity.INFO
                category = DriftCategory.BENIGN_DEFAULT
                desc = (
                    f"Runtime grants default capability {cap} which "
                    f"was not explicitly dropped in the spec"
                )
            else:
                # Non-default cap present unexpectedly
                severity = DriftSeverity.WARNING
                category = DriftCategory.UNEXPECTED_ADDITION
                desc = (
                    f"Runtime grants capability {cap} which was "
                    f"not requested in the spec"
                )

            findings.append(DriftFinding(
                field_name="capabilities",
                description=desc,
                severity=severity,
                category=category,
                declared_value=f"not in spec (add={spec.capabilities_add})",
                actual_value=cap,
            ))

        # ── Capabilities declared but missing at runtime ───────────
        missing = expected - actual
        for cap in sorted(missing):
            # A requested cap is missing — usually INFO (runtime
            # may strip caps), but if it was explicitly added then
            # it's a WARNING.
            if cap in {normalize_cap_name(c) for c in spec.capabilities_add}:
                severity = DriftSeverity.WARNING
                desc = (
                    f"Spec explicitly adds {cap} but it is not "
                    f"present in the runtime capability set"
                )
            else:
                severity = DriftSeverity.INFO
                desc = (
                    f"Expected default capability {cap} is not "
                    f"present at runtime (may have been stripped)"
                )

            findings.append(DriftFinding(
                field_name="capabilities",
                description=desc,
                severity=severity,
                category=DriftCategory.SECURITY_DEGRADATION
                if severity == DriftSeverity.WARNING
                else DriftCategory.BENIGN_DEFAULT,
                declared_value=cap,
                actual_value="absent",
            ))

        return findings

    # ── 4. Seccomp profile ─────────────────────────────────────────

    def _check_seccomp(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        spec_type = (spec.seccomp_profile_type or "").lower()
        runtime_has_seccomp = runtime.seccomp_profile is not None

        if spec_type in ("runtimedefault", "localhost"):
            # Spec declares a seccomp profile
            if not runtime_has_seccomp:
                # CRITICAL: declared seccomp but runtime is unconfined
                findings.append(DriftFinding(
                    field_name="seccompProfile",
                    description=(
                        f"Spec declares seccomp type "
                        f"'{spec.seccomp_profile_type}' but the "
                        f"runtime has NO seccomp filter (unconfined)"
                    ),
                    severity=DriftSeverity.CRITICAL,
                    category=DriftCategory.SECCOMP_MISMATCH,
                    declared_value=spec.seccomp_profile_type or "",
                    actual_value="unconfined (null)",
                ))
        elif spec_type in ("unconfined", ""):
            # Spec does not declare seccomp (or declares Unconfined)
            if runtime_has_seccomp:
                # INFO: runtime applied a default profile — more secure
                findings.append(DriftFinding(
                    field_name="seccompProfile",
                    description=(
                        "Spec does not declare a seccomp profile but "
                        "the runtime applied one (likely kubelet "
                        "--seccomp-default). This is more secure."
                    ),
                    severity=DriftSeverity.INFO,
                    category=DriftCategory.BENIGN_DEFAULT,
                    declared_value=spec.seccomp_profile_type or "none",
                    actual_value="profile applied",
                ))

        return findings

    # ── 5. Read-only root filesystem ───────────────────────────────

    def _check_rootfs(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        if spec.read_only_root_filesystem and not runtime.root_readonly:
            # CRITICAL: declared read-only but runtime is writable
            findings.append(DriftFinding(
                field_name="readOnlyRootFilesystem",
                description=(
                    "Spec declares readOnlyRootFilesystem=true but "
                    "the runtime root filesystem is writable"
                ),
                severity=DriftSeverity.CRITICAL,
                category=DriftCategory.ROOTFS_MISMATCH,
                declared_value="true",
                actual_value="false",
            ))
        elif not spec.read_only_root_filesystem and runtime.root_readonly:
            # INFO: runtime is stricter than spec
            findings.append(DriftFinding(
                field_name="readOnlyRootFilesystem",
                description=(
                    "Spec does not require read-only rootfs but "
                    "the runtime set it to read-only (more secure)"
                ),
                severity=DriftSeverity.INFO,
                category=DriftCategory.BENIGN_DEFAULT,
                declared_value="false",
                actual_value="true",
            ))

        return findings

    # ── 6. Privilege escalation (noNewPrivileges) ──────────────────

    def _check_privilege_escalation(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        # allowPrivilegeEscalation=false maps to noNewPrivileges=true
        # (inverted logic)
        if spec.allow_privilege_escalation is False:
            # Spec wants no privilege escalation
            if not runtime.no_new_privileges:
                findings.append(DriftFinding(
                    field_name="allowPrivilegeEscalation",
                    description=(
                        "Spec declares allowPrivilegeEscalation=false "
                        "but runtime noNewPrivileges is not set"
                    ),
                    severity=DriftSeverity.CRITICAL,
                    category=DriftCategory.PRIVILEGE_ESCALATION,
                    declared_value="false (noNewPrivs=true expected)",
                    actual_value="noNewPrivileges=false",
                ))
        elif spec.allow_privilege_escalation is None:
            # Spec doesn't specify; if runtime enforces it, that's good
            if runtime.no_new_privileges:
                findings.append(DriftFinding(
                    field_name="allowPrivilegeEscalation",
                    description=(
                        "Spec does not set allowPrivilegeEscalation "
                        "but runtime enforces noNewPrivileges (more secure)"
                    ),
                    severity=DriftSeverity.INFO,
                    category=DriftCategory.BENIGN_DEFAULT,
                    declared_value="not specified",
                    actual_value="noNewPrivileges=true",
                ))

        return findings

    # ── 7. Host namespaces (PID, Network, IPC) ─────────────────────

    def _check_namespaces(
        self, spec: SpecSecurityState, runtime: RuntimeSecurityState
    ) -> List[DriftFinding]:
        findings = []

        ns_checks = [
            ("hostPID", spec.host_pid, runtime.namespace_pid),
            ("hostNetwork", spec.host_network, runtime.namespace_network),
            ("hostIPC", spec.host_ipc, runtime.namespace_ipc),
        ]

        for field_name, spec_host, runtime_ns_mode in ns_checks:
            if runtime_ns_mode is None:
                continue  # Data not available

            runtime_is_host = (runtime_ns_mode == 2)

            if not spec_host and runtime_is_host:
                # CRITICAL: not declared but using host namespace
                findings.append(DriftFinding(
                    field_name=field_name,
                    description=(
                        f"Spec declares {field_name}=false but the "
                        f"container uses the host namespace at runtime"
                    ),
                    severity=DriftSeverity.CRITICAL,
                    category=DriftCategory.NAMESPACE_MISMATCH,
                    declared_value="false",
                    actual_value="host (mode=2)",
                ))
            elif spec_host and not runtime_is_host:
                # INFO: declared host but runtime isolated (stricter)
                findings.append(DriftFinding(
                    field_name=field_name,
                    description=(
                        f"Spec declares {field_name}=true but the "
                        f"runtime uses an isolated namespace"
                    ),
                    severity=DriftSeverity.INFO,
                    category=DriftCategory.BENIGN_DEFAULT,
                    declared_value="true",
                    actual_value=f"isolated (mode={runtime_ns_mode})",
                ))

        return findings
