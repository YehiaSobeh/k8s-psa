"""
Evaluation test suite: mirrors the 7 test pods exactly.

These tests verify the drift detector logic produces the expected
results for each evaluation scenario WITHOUT needing a Kubernetes cluster.
They construct SpecSecurityState + RuntimeSecurityState manually to simulate
what Docker/Minikube would return.
"""

import unittest
from src.models import SpecSecurityState, RuntimeSecurityState, DriftSeverity
from src.drift_detector import DriftDetector
from src.normalizer import DEFAULT_CAPABILITIES, ALL_CAPABILITIES


class TestEvaluationScenarios(unittest.TestCase):

    def setUp(self):
        self.detector = DriftDetector()

    # ── Helper ─────────────────────────────────────────────────────

    def _count(self, report, severity):
        return sum(1 for f in report.findings if f.severity == severity)

    # ══════════════════════════════════════════════════════════════
    # TEST 1: Fully hardened — expect 0 critical, 0 warning
    # ══════════════════════════════════════════════════════════════

    def test_1_fully_hardened_no_drift(self):
        """Pod 1: all security settings enabled, runtime matches perfectly."""
        spec = SpecSecurityState(
            container_name="secure-app", pod_name="test-1-fully-hardened",
            namespace="default",
            privileged=False,
            run_as_user=1000, run_as_group=1000,
            read_only_root_filesystem=True,
            allow_privilege_escalation=False,
            capabilities_add=[], capabilities_drop=["ALL"],
            seccomp_profile_type="RuntimeDefault",
            host_network=False, host_pid=False, host_ipc=False,
        )
        runtime = RuntimeSecurityState(
            container_id="test1", container_name="secure-app",
            uid=1000, gid=1000,
            capabilities_effective=[], capabilities_bounding=[],
            capabilities_permitted=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=True,
            no_new_privileges=True,
            masked_paths=["/proc/kcore"],
            namespace_pid=0, namespace_network=0, namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)

        self.assertEqual(self._count(report, DriftSeverity.CRITICAL), 0,
            f"Pod 1 should have 0 CRITICAL: {[f.description for f in report.findings if f.severity == DriftSeverity.CRITICAL]}")
        self.assertEqual(self._count(report, DriftSeverity.WARNING), 0,
            f"Pod 1 should have 0 WARNING: {[f.description for f in report.findings if f.severity == DriftSeverity.WARNING]}")

    # ══════════════════════════════════════════════════════════════
    # TEST 2: No security context — expect 0 critical, 0 warning
    # ══════════════════════════════════════════════════════════════

    def test_2_no_security_context(self):
        """Pod 2: no securityContext → runtime uses defaults, no drift."""
        spec = SpecSecurityState(
            container_name="bare-app", pod_name="test-2-no-security",
            namespace="default",
            # Everything at default (False/None/empty)
        )
        runtime = RuntimeSecurityState(
            container_id="test2", container_name="bare-app",
            uid=0, gid=0,  # root from image
            capabilities_effective=sorted(DEFAULT_CAPABILITIES),
            capabilities_bounding=sorted(DEFAULT_CAPABILITIES),
            capabilities_permitted=[],
            seccomp_profile=None,  # unconfined
            root_readonly=False,
            no_new_privileges=False,
            masked_paths=["/proc/kcore"],
            namespace_pid=0, namespace_network=0, namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)

        self.assertEqual(self._count(report, DriftSeverity.CRITICAL), 0,
            "Pod 2 should have 0 CRITICAL (no declarations to violate)")
        self.assertEqual(self._count(report, DriftSeverity.WARNING), 0,
            "Pod 2 should have 0 WARNING (defaults match expected defaults)")

    # ══════════════════════════════════════════════════════════════
    # TEST 3: Privileged + seccomp — expect 1 CRITICAL, ~27 WARNING
    # ══════════════════════════════════════════════════════════════

    def test_3_privileged_seccomp_stripped(self):
        """Pod 3: THE KEY SCENARIO. Docker strips seccomp from privileged."""
        spec = SpecSecurityState(
            container_name="priv-seccomp",
            pod_name="test-3-privileged-seccomp",
            namespace="default",
            privileged=True,
            seccomp_profile_type="RuntimeDefault",
            capabilities_add=[], capabilities_drop=[],
        )
        # Docker with privileged=true: ALL caps, no seccomp, no masked paths
        runtime = RuntimeSecurityState(
            container_id="test3", container_name="priv-seccomp",
            uid=0, gid=0,
            capabilities_effective=sorted(ALL_CAPABILITIES),
            capabilities_bounding=sorted(ALL_CAPABILITIES),
            capabilities_permitted=[],
            seccomp_profile=None,  # STRIPPED by Docker!
            root_readonly=False,
            no_new_privileges=False,
            masked_paths=[],  # also stripped
            namespace_pid=0, namespace_network=0, namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)

        # CRITICAL: seccomp declared but stripped
        critical = [f for f in report.findings if f.severity == DriftSeverity.CRITICAL]
        seccomp_critical = [f for f in critical if f.field_name == "seccompProfile"]
        self.assertEqual(len(seccomp_critical), 1,
            "Pod 3 MUST detect seccomp stripped — this is the thesis centerpiece")
        self.assertIn("unconfined", seccomp_critical[0].actual_value)

        # WARNING: ~27 unexpected capabilities (ALL minus 14 defaults)
        warnings = [f for f in report.findings if f.severity == DriftSeverity.WARNING]
        cap_warnings = [f for f in warnings if f.field_name == "capabilities"]
        expected_extra = len(ALL_CAPABILITIES) - len(DEFAULT_CAPABILITIES)
        self.assertEqual(len(cap_warnings), expected_extra,
            f"Pod 3 should have {expected_extra} capability warnings, got {len(cap_warnings)}")

    # ══════════════════════════════════════════════════════════════
    # TEST 4: Privileged NO seccomp — expect 0 CRITICAL, ~27 WARNING
    # ══════════════════════════════════════════════════════════════

    def test_4_privileged_no_seccomp_control(self):
        """Pod 4: Control for Test 3. Same runtime but no seccomp declared."""
        spec = SpecSecurityState(
            container_name="priv-no-seccomp",
            pod_name="test-4-privileged-no-seccomp",
            namespace="default",
            privileged=True,
            run_as_user=0,
            seccomp_profile_type=None,  # NOT declared
            capabilities_add=[], capabilities_drop=[],
        )
        runtime = RuntimeSecurityState(
            container_id="test4", container_name="priv-no-seccomp",
            uid=0, gid=0,
            capabilities_effective=sorted(ALL_CAPABILITIES),
            capabilities_bounding=sorted(ALL_CAPABILITIES),
            capabilities_permitted=[],
            seccomp_profile=None,  # unconfined — matches spec this time
            root_readonly=False,
            no_new_privileges=False,
            masked_paths=[],
            namespace_pid=0, namespace_network=0, namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)

        # CRITICAL: 0 — no seccomp declared, so no mismatch
        critical = [f for f in report.findings if f.severity == DriftSeverity.CRITICAL]
        seccomp_critical = [f for f in critical if f.field_name == "seccompProfile"]
        self.assertEqual(len(seccomp_critical), 0,
            "Pod 4 should have 0 seccomp CRITICAL (not declared)")

        # WARNING: same ~27 cap warnings as Test 3
        warnings = [f for f in report.findings if f.severity == DriftSeverity.WARNING]
        cap_warnings = [f for f in warnings if f.field_name == "capabilities"]
        expected_extra = len(ALL_CAPABILITIES) - len(DEFAULT_CAPABILITIES)
        self.assertEqual(len(cap_warnings), expected_extra,
            f"Pod 4 should still have {expected_extra} cap warnings")

    # ══════════════════════════════════════════════════════════════
    # TEST 3 vs 4: The critical comparison
    # ══════════════════════════════════════════════════════════════

    def test_3_vs_4_seccomp_is_the_only_difference(self):
        """Prove that Test 3 and Test 4 differ ONLY in seccomp CRITICAL."""
        # Run both
        spec3 = SpecSecurityState(
            container_name="s3", pod_name="p3", namespace="d",
            privileged=True, seccomp_profile_type="RuntimeDefault",
            capabilities_add=[], capabilities_drop=[],
        )
        spec4 = SpecSecurityState(
            container_name="s4", pod_name="p4", namespace="d",
            privileged=True, seccomp_profile_type=None,
            capabilities_add=[], capabilities_drop=[],
        )
        # Same runtime for both
        runtime = RuntimeSecurityState(
            container_id="t", container_name="s3",
            uid=0, capabilities_effective=sorted(ALL_CAPABILITIES),
            capabilities_bounding=sorted(ALL_CAPABILITIES),
            seccomp_profile=None, root_readonly=False,
            no_new_privileges=False, masked_paths=[],
        )

        runtime2 = RuntimeSecurityState(
            container_id="t", container_name="s4",
            uid=0, capabilities_effective=sorted(ALL_CAPABILITIES),
            capabilities_bounding=sorted(ALL_CAPABILITIES),
            seccomp_profile=None, root_readonly=False,
            no_new_privileges=False, masked_paths=[],
        )

        r3 = self.detector.detect(spec3, runtime)
        r4 = self.detector.detect(spec4, runtime2)

        crit3 = self._count(r3, DriftSeverity.CRITICAL)
        crit4 = self._count(r4, DriftSeverity.CRITICAL)
        warn3 = self._count(r3, DriftSeverity.WARNING)
        warn4 = self._count(r4, DriftSeverity.WARNING)

        self.assertEqual(crit3, 1, "Test 3 must have exactly 1 CRITICAL")
        self.assertEqual(crit4, 0, "Test 4 must have exactly 0 CRITICAL")
        self.assertEqual(warn3, warn4, "Both must have same WARNING count")

    # ══════════════════════════════════════════════════════════════
    # TEST 5: Partial security — expect 0 critical, 0 warning
    # ══════════════════════════════════════════════════════════════

    def test_5_partial_security(self):
        """Pod 5: drop 2 specific caps, keep rest. No drift expected."""
        spec = SpecSecurityState(
            container_name="partial-app",
            pod_name="test-5-partial-security",
            namespace="default",
            run_as_user=1000,
            read_only_root_filesystem=False,
            seccomp_profile_type="RuntimeDefault",
            capabilities_add=[],
            capabilities_drop=["NET_RAW", "SYS_ADMIN"],
        )
        # Runtime: defaults minus the 2 dropped
        remaining = sorted(DEFAULT_CAPABILITIES - {"CAP_NET_RAW", "CAP_SYS_ADMIN"})
        runtime = RuntimeSecurityState(
            container_id="test5", container_name="partial-app",
            uid=1000, gid=0,
            capabilities_effective=remaining,
            capabilities_bounding=remaining,
            capabilities_permitted=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=False,
            no_new_privileges=False,
            namespace_pid=0, namespace_network=0, namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)

        self.assertEqual(self._count(report, DriftSeverity.CRITICAL), 0,
            "Pod 5 should have 0 CRITICAL")
        self.assertEqual(self._count(report, DriftSeverity.WARNING), 0,
            "Pod 5 should have 0 WARNING (partial drop matches)")

    # ══════════════════════════════════════════════════════════════
    # TEST 6: Privilege escalation — depends on Docker behavior
    # ══════════════════════════════════════════════════════════════

    def test_6_privesc_enforced(self):
        """Pod 6a: Docker correctly sets noNewPrivileges → 0 critical."""
        spec = SpecSecurityState(
            container_name="no-privesc-app",
            pod_name="test-6-no-privesc",
            namespace="default",
            run_as_user=1000,
            read_only_root_filesystem=True,
            allow_privilege_escalation=False,
            capabilities_add=[], capabilities_drop=["ALL"],
            seccomp_profile_type="RuntimeDefault",
        )
        runtime = RuntimeSecurityState(
            container_id="test6a", container_name="no-privesc-app",
            uid=1000, capabilities_effective=[], capabilities_bounding=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=True,
            no_new_privileges=True,  # Correctly enforced
        )

        report = self.detector.detect(spec, runtime)
        self.assertEqual(self._count(report, DriftSeverity.CRITICAL), 0)

    def test_6_privesc_not_enforced(self):
        """Pod 6b: Docker does NOT set noNewPrivileges → 1 CRITICAL."""
        spec = SpecSecurityState(
            container_name="no-privesc-app",
            pod_name="test-6-no-privesc",
            namespace="default",
            allow_privilege_escalation=False,
            capabilities_add=[], capabilities_drop=["ALL"],
            seccomp_profile_type="RuntimeDefault",
        )
        runtime = RuntimeSecurityState(
            container_id="test6b", container_name="no-privesc-app",
            uid=1000, capabilities_effective=[], capabilities_bounding=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=True,
            no_new_privileges=False,  # NOT enforced — drift!
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]
        pe = [f for f in critical if f.field_name == "allowPrivilegeEscalation"]
        self.assertEqual(len(pe), 1,
            "Should detect noNewPrivileges not enforced as CRITICAL")

    # ══════════════════════════════════════════════════════════════
    # TEST 7: Host namespaces — expect INFO findings
    # ══════════════════════════════════════════════════════════════

    def test_7_host_namespaces_docker_isolated(self):
        """Pod 7: spec says host=true but Docker shows isolated (mode=0).
        This is the known Minikube/Docker behavior from your real data."""
        spec = SpecSecurityState(
            container_name="host-ns-app",
            pod_name="test-7-host-namespaces",
            namespace="default",
            host_network=True, host_pid=True, host_ipc=True,
            capabilities_add=["SYS_ADMIN"], capabilities_drop=[],
        )
        runtime = RuntimeSecurityState(
            container_id="test7", container_name="host-ns-app",
            uid=0,
            capabilities_effective=sorted(DEFAULT_CAPABILITIES | {"CAP_SYS_ADMIN"}),
            capabilities_bounding=sorted(DEFAULT_CAPABILITIES | {"CAP_SYS_ADMIN"}),
            seccomp_profile=None,
            root_readonly=False,
            no_new_privileges=False,
            namespace_pid=0,      # Docker shows isolated
            namespace_network=0,  # Docker shows isolated
            namespace_ipc=0,      # Docker shows isolated
        )

        report = self.detector.detect(spec, runtime)

        # No CRITICAL: runtime is MORE restrictive, not less
        self.assertEqual(self._count(report, DriftSeverity.CRITICAL), 0)

        # INFO: 3 namespace findings (spec=host, runtime=isolated)
        info = [f for f in report.findings if f.severity == DriftSeverity.INFO]
        ns_info = [f for f in info if f.field_name in ("hostPID", "hostNetwork", "hostIPC")]
        self.assertEqual(len(ns_info), 3,
            "Should have 3 INFO findings for namespace mismatch")

    def test_7_host_namespaces_actually_host(self):
        """Pod 7 alternative: if Docker DOES report host mode → 0 findings."""
        spec = SpecSecurityState(
            container_name="host-ns-app",
            pod_name="test-7-host-namespaces",
            namespace="default",
            host_network=True, host_pid=True, host_ipc=True,
            capabilities_add=["SYS_ADMIN"], capabilities_drop=[],
        )
        runtime = RuntimeSecurityState(
            container_id="test7b", container_name="host-ns-app",
            uid=0,
            capabilities_effective=sorted(DEFAULT_CAPABILITIES | {"CAP_SYS_ADMIN"}),
            capabilities_bounding=sorted(DEFAULT_CAPABILITIES | {"CAP_SYS_ADMIN"}),
            seccomp_profile=None,
            root_readonly=False, no_new_privileges=False,
            namespace_pid=2,      # host
            namespace_network=2,  # host
            namespace_ipc=2,      # host
        )

        report = self.detector.detect(spec, runtime)
        # Everything matches: spec=host, runtime=host
        ns_findings = [f for f in report.findings
                       if f.field_name in ("hostPID", "hostNetwork", "hostIPC")]
        self.assertEqual(len(ns_findings), 0, "No NS findings when both agree")


if __name__ == "__main__":
    unittest.main()
