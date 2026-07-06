"""
Test suite for k8s-psa: covers normalizer, spec extractor, runtime
inspector parsing, and drift detector logic.

All tests run without a Kubernetes cluster — they use fixture JSON
files and in-memory data structures.
"""

import json
import os
import unittest
from pathlib import Path

from src.models import (
    SpecSecurityState,
    RuntimeSecurityState,
    DriftSeverity,
    DriftCategory,
)
from src.normalizer import (
    compute_expected_capabilities,
    normalize_cap_name,
    is_default_capability,
    DEFAULT_CAPABILITIES,
)
from src.spec_extractor import extract_spec_states
from src.drift_detector import DriftDetector
from src.runtime_inspector import parse_crictl_json, parse_docker_json

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with open(FIXTURES / name) as f:
        return json.load(f)


# ═══════════════════════════════════════════════════════════════════
#  Normalizer Tests
# ═══════════════════════════════════════════════════════════════════


class TestNormalizer(unittest.TestCase):

    def test_normalize_cap_name_adds_prefix(self):
        self.assertEqual(normalize_cap_name("SYS_ADMIN"), "CAP_SYS_ADMIN")

    def test_normalize_cap_name_preserves_prefix(self):
        self.assertEqual(normalize_cap_name("CAP_NET_RAW"), "CAP_NET_RAW")

    def test_normalize_cap_name_uppercase(self):
        self.assertEqual(normalize_cap_name("cap_chown"), "CAP_CHOWN")

    def test_is_default_capability(self):
        self.assertTrue(is_default_capability("CAP_CHOWN"))
        self.assertTrue(is_default_capability("CHOWN"))
        self.assertFalse(is_default_capability("CAP_SYS_ADMIN"))

    def test_expected_caps_no_spec(self):
        """No add/drop → expect all defaults."""
        expected = compute_expected_capabilities([], [])
        self.assertEqual(expected, DEFAULT_CAPABILITIES)

    def test_expected_caps_drop_all(self):
        """drop=ALL, add=nothing → expect empty set."""
        expected = compute_expected_capabilities([], ["ALL"])
        self.assertEqual(expected, set())

    def test_expected_caps_drop_all_add_one(self):
        """drop=ALL, add=NET_RAW → expect only NET_RAW."""
        expected = compute_expected_capabilities(["NET_RAW"], ["ALL"])
        self.assertEqual(expected, {"CAP_NET_RAW"})

    def test_expected_caps_add_extra(self):
        """Add SYS_ADMIN → defaults + SYS_ADMIN."""
        expected = compute_expected_capabilities(["SYS_ADMIN"], [])
        self.assertIn("CAP_SYS_ADMIN", expected)
        self.assertTrue(DEFAULT_CAPABILITIES.issubset(expected))

    def test_expected_caps_drop_specific(self):
        """Drop NET_RAW → defaults minus NET_RAW."""
        expected = compute_expected_capabilities([], ["NET_RAW"])
        self.assertNotIn("CAP_NET_RAW", expected)
        self.assertIn("CAP_CHOWN", expected)


# ═══════════════════════════════════════════════════════════════════
#  Spec Extractor Tests
# ═══════════════════════════════════════════════════════════════════


class TestSpecExtractor(unittest.TestCase):

    def test_extract_secure_pod(self):
        pod = {
            "metadata": {"name": "secure-pod", "namespace": "default"},
            "spec": {
                "hostNetwork": False,
                "hostPID": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "good-container",
                    "securityContext": {
                        "runAsUser": 1000,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }],
            },
        }
        states = extract_spec_states(pod)
        self.assertEqual(len(states), 1)

        s = states[0]
        self.assertEqual(s.container_name, "good-container")
        self.assertEqual(s.pod_name, "secure-pod")
        self.assertFalse(s.privileged)
        self.assertEqual(s.run_as_user, 1000)
        self.assertTrue(s.read_only_root_filesystem)
        self.assertFalse(s.allow_privilege_escalation)
        self.assertEqual(s.capabilities_drop, ["ALL"])
        self.assertEqual(s.seccomp_profile_type, "RuntimeDefault")
        self.assertFalse(s.host_network)
        self.assertFalse(s.host_pid)

    def test_extract_vulnerable_pod(self):
        pod = {
            "metadata": {"name": "vuln-pod", "namespace": "default"},
            "spec": {
                "hostNetwork": True,
                "hostPID": True,
                "containers": [{
                    "name": "bad-container",
                    "securityContext": {
                        "privileged": True,
                        "runAsUser": 0,
                        "capabilities": {"add": ["SYS_ADMIN", "NET_RAW"]},
                    },
                }],
            },
        }
        states = extract_spec_states(pod)
        s = states[0]
        self.assertTrue(s.privileged)
        self.assertEqual(s.run_as_user, 0)
        self.assertTrue(s.host_network)
        self.assertTrue(s.host_pid)
        self.assertIn("SYS_ADMIN", s.capabilities_add)

    def test_extract_multiple_containers(self):
        pod = {
            "metadata": {"name": "multi", "namespace": "ns"},
            "spec": {
                "containers": [
                    {"name": "app", "securityContext": {"runAsUser": 1000}},
                    {"name": "sidecar", "securityContext": {"runAsUser": 2000}},
                ],
            },
        }
        states = extract_spec_states(pod)
        self.assertEqual(len(states), 2)
        self.assertEqual(states[0].run_as_user, 1000)
        self.assertEqual(states[1].run_as_user, 2000)


# ═══════════════════════════════════════════════════════════════════
#  Runtime Inspector Parsing Tests
# ═══════════════════════════════════════════════════════════════════


class TestRuntimeInspectorParsing(unittest.TestCase):

    def test_parse_secure_container(self):
        data = load_fixture("crictl_inspect_secure.json")
        state = parse_crictl_json(data)

        self.assertIsNotNone(state)
        self.assertEqual(state.container_name, "good-container")
        self.assertEqual(state.uid, 1000)
        self.assertEqual(state.gid, 1000)
        self.assertTrue(state.root_readonly)
        self.assertTrue(state.no_new_privileges)
        self.assertEqual(state.capabilities_effective, [])
        self.assertIsNotNone(state.seccomp_profile)  # Has seccomp
        self.assertFalse(state.is_effectively_privileged)
        self.assertTrue(len(state.masked_paths) > 0)

    def test_parse_privileged_container(self):
        data = load_fixture("crictl_inspect_privileged.json")
        state = parse_crictl_json(data)

        self.assertIsNotNone(state)
        self.assertEqual(state.container_name, "bad-container")
        self.assertEqual(state.uid, 0)
        self.assertFalse(state.root_readonly)
        self.assertFalse(state.no_new_privileges)
        self.assertTrue(state.is_effectively_privileged)
        self.assertIn("CAP_SYS_ADMIN", state.capabilities_bounding)
        self.assertIsNone(state.seccomp_profile)  # No seccomp
        self.assertEqual(len(state.masked_paths), 0)  # No masked paths

    def test_parse_seccomp_drift_container(self):
        data = load_fixture("crictl_inspect_seccomp_drift.json")
        state = parse_crictl_json(data)

        self.assertIsNotNone(state)
        self.assertEqual(state.uid, 1000)
        self.assertTrue(state.root_readonly)
        self.assertIsNone(state.seccomp_profile)  # Seccomp stripped!
        self.assertFalse(state.is_effectively_privileged)


# ═══════════════════════════════════════════════════════════════════
#  Docker Backend Parsing Tests
# ═══════════════════════════════════════════════════════════════════


class TestDockerInspectorParsing(unittest.TestCase):
    """Test docker inspect JSON parsing (for Minikube Docker driver)."""

    def test_parse_docker_secure(self):
        data = load_fixture("docker_inspect_secure.json")
        state = parse_docker_json(data)

        self.assertIsNotNone(state)
        self.assertEqual(state.container_name, "good-container")
        self.assertEqual(state.uid, 1000)
        self.assertEqual(state.gid, 1000)
        self.assertTrue(state.root_readonly)
        self.assertTrue(state.no_new_privileges)
        self.assertIsNotNone(state.seccomp_profile)  # Has seccomp
        # CapDrop=ALL means effective caps should be empty
        self.assertEqual(state.capabilities_effective, [])
        self.assertFalse(state.is_effectively_privileged)
        self.assertEqual(state.namespace_pid, 0)  # Not host
        self.assertEqual(state.namespace_network, 0)

    def test_parse_docker_privileged(self):
        data = load_fixture("docker_inspect_privileged.json")
        state = parse_docker_json(data)

        self.assertIsNotNone(state)
        self.assertEqual(state.container_name, "bad-container")
        self.assertEqual(state.uid, 0)  # No User set → root
        self.assertFalse(state.root_readonly)
        self.assertTrue(state.is_effectively_privileged)
        self.assertIn("CAP_SYS_ADMIN", state.capabilities_effective)
        self.assertIsNone(state.seccomp_profile)  # Privileged → no seccomp
        self.assertEqual(state.namespace_pid, 2)  # host
        self.assertEqual(state.namespace_network, 2)  # host
        self.assertEqual(len(state.masked_paths), 0)

    def test_docker_k8s_label_extraction(self):
        """Verify K8s container name is extracted from labels."""
        data = load_fixture("docker_inspect_secure.json")
        state = parse_docker_json(data)
        # Should use io.kubernetes.container.name, not the Docker name
        self.assertEqual(state.container_name, "good-container")

    def test_docker_integration_drift_secure(self):
        """End-to-end: secure spec vs secure Docker runtime."""
        pod = {
            "metadata": {"name": "secure-pod", "namespace": "default"},
            "spec": {
                "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "good-container",
                    "securityContext": {
                        "runAsUser": 1000,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }],
            },
        }
        spec_states = extract_spec_states(pod)
        docker_data = load_fixture("docker_inspect_secure.json")
        runtime_state = parse_docker_json(docker_data)

        detector = DriftDetector()
        report = detector.detect(spec_states[0], runtime_state)
        critical = [f for f in report.findings if f.severity == DriftSeverity.CRITICAL]
        self.assertEqual(len(critical), 0,
                         f"Secure pod should have no critical drift: "
                         f"{[f.description for f in critical]}")

    def test_docker_integration_drift_privileged(self):
        """End-to-end: non-privileged spec vs privileged Docker runtime."""
        pod = {
            "metadata": {"name": "drift-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "bad-container",
                    "securityContext": {
                        "privileged": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }],
            },
        }
        spec_states = extract_spec_states(pod)
        docker_data = load_fixture("docker_inspect_privileged.json")
        runtime_state = parse_docker_json(docker_data)

        detector = DriftDetector()
        report = detector.detect(spec_states[0], runtime_state)
        critical = [f for f in report.findings if f.severity == DriftSeverity.CRITICAL]
        self.assertTrue(len(critical) >= 1, "Should detect privileged drift")
        priv_findings = [f for f in critical if f.field_name == "privileged"]
        self.assertTrue(len(priv_findings) >= 1)


# ═══════════════════════════════════════════════════════════════════
#  Drift Detector Tests
# ═══════════════════════════════════════════════════════════════════


class TestDriftDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DriftDetector()

    # ── Test: No drift (perfectly matched) ─────────────────────────

    def test_no_drift_secure_pod(self):
        """A secure pod with matching runtime state should produce
        no critical or warning findings."""
        spec = SpecSecurityState(
            container_name="good",
            pod_name="secure-pod",
            namespace="default",
            privileged=False,
            run_as_user=1000,
            read_only_root_filesystem=True,
            allow_privilege_escalation=False,
            capabilities_add=[],
            capabilities_drop=["ALL"],
            seccomp_profile_type="RuntimeDefault",
        )
        runtime = RuntimeSecurityState(
            container_id="abc123",
            container_name="good",
            uid=1000,
            gid=0,
            capabilities_bounding=[],
            capabilities_effective=[],
            capabilities_permitted=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=True,
            no_new_privileges=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]
        warnings = [f for f in report.findings
                    if f.severity == DriftSeverity.WARNING]

        self.assertEqual(len(critical), 0,
                         f"Unexpected critical findings: {critical}")
        self.assertEqual(len(warnings), 0,
                         f"Unexpected warning findings: {warnings}")

    # ── Test: CRITICAL — seccomp declared but missing ──────────────

    def test_critical_seccomp_stripped(self):
        """Spec declares RuntimeDefault seccomp but runtime has none."""
        spec = SpecSecurityState(
            container_name="drifted",
            pod_name="drift-pod",
            namespace="default",
            seccomp_profile_type="RuntimeDefault",
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="drift001",
            container_name="drifted",
            uid=1000,
            capabilities_effective=[],
            seccomp_profile=None,  # STRIPPED!
            root_readonly=True,
            no_new_privileges=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        self.assertTrue(len(critical) >= 1)
        seccomp_findings = [f for f in critical
                           if f.field_name == "seccompProfile"]
        self.assertEqual(len(seccomp_findings), 1)
        self.assertEqual(seccomp_findings[0].category,
                         DriftCategory.SECCOMP_MISMATCH)

    # ── Test: CRITICAL — user drift (declared non-root, runs root) ─

    def test_critical_user_drift_to_root(self):
        """Spec says runAsUser=1000 but runtime runs as UID 0."""
        spec = SpecSecurityState(
            container_name="user-drift",
            pod_name="drift-pod",
            namespace="default",
            run_as_user=1000,
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="user001",
            container_name="user-drift",
            uid=0,  # ROOT!
            capabilities_effective=[],
            root_readonly=False,
            no_new_privileges=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        user_findings = [f for f in critical if f.field_name == "runAsUser"]
        self.assertEqual(len(user_findings), 1)
        self.assertIn("UID 0", user_findings[0].description)

    # ── Test: CRITICAL — rootfs declared readonly but writable ─────

    def test_critical_rootfs_writable(self):
        """Spec declares readOnlyRootFilesystem=true but runtime is writable."""
        spec = SpecSecurityState(
            container_name="rootfs-drift",
            pod_name="drift-pod",
            namespace="default",
            read_only_root_filesystem=True,
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="rootfs001",
            container_name="rootfs-drift",
            uid=1000,
            capabilities_effective=[],
            root_readonly=False,  # WRITABLE!
            no_new_privileges=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        rootfs_findings = [f for f in critical
                          if f.field_name == "readOnlyRootFilesystem"]
        self.assertEqual(len(rootfs_findings), 1)

    # ── Test: CRITICAL — not declared privileged but effectively is ─

    def test_critical_undeclared_privileged(self):
        """Spec says privileged=false but runtime has all caps + no seccomp."""
        spec = SpecSecurityState(
            container_name="priv-drift",
            pod_name="drift-pod",
            namespace="default",
            privileged=False,
            capabilities_drop=["ALL"],
        )
        # Build a runtime state that looks privileged
        data = load_fixture("crictl_inspect_privileged.json")
        runtime = parse_crictl_json(data)
        runtime.container_name = "priv-drift"

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        priv_findings = [f for f in critical
                        if f.field_name == "privileged"]
        self.assertEqual(len(priv_findings), 1)

    # ── Test: CRITICAL — privilege escalation not blocked ───────────

    def test_critical_privilege_escalation(self):
        """Spec says allowPrivilegeEscalation=false but runtime allows it."""
        spec = SpecSecurityState(
            container_name="privesc",
            pod_name="drift-pod",
            namespace="default",
            allow_privilege_escalation=False,
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="privesc001",
            container_name="privesc",
            uid=1000,
            capabilities_effective=[],
            no_new_privileges=False,  # NOT ENFORCED!
            root_readonly=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        pe_findings = [f for f in critical
                       if f.field_name == "allowPrivilegeEscalation"]
        self.assertEqual(len(pe_findings), 1)

    # ── Test: CRITICAL — host namespace used but not declared ──────

    def test_critical_host_namespace_drift(self):
        """Spec says hostPID=false but runtime uses host PID namespace."""
        spec = SpecSecurityState(
            container_name="ns-drift",
            pod_name="drift-pod",
            namespace="default",
            host_pid=False,
            host_network=False,
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="ns001",
            container_name="ns-drift",
            uid=1000,
            capabilities_effective=[],
            root_readonly=True,
            no_new_privileges=True,
            namespace_pid=2,       # HOST!
            namespace_network=0,   # Isolated
            namespace_ipc=0,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]

        ns_findings = [f for f in critical if f.field_name == "hostPID"]
        self.assertEqual(len(ns_findings), 1)

    # ── Test: INFO — runtime stricter than spec ────────────────────

    def test_info_runtime_stricter(self):
        """Runtime applies seccomp and readonly rootfs even though
        spec doesn't require it — should be INFO, not warning."""
        spec = SpecSecurityState(
            container_name="relaxed",
            pod_name="relaxed-pod",
            namespace="default",
            read_only_root_filesystem=False,
            seccomp_profile_type=None,
            capabilities_drop=["ALL"],
        )
        runtime = RuntimeSecurityState(
            container_id="relaxed001",
            container_name="relaxed",
            uid=1000,
            capabilities_effective=[],
            seccomp_profile={"defaultAction": "SCMP_ACT_ERRNO"},
            root_readonly=True,  # Stricter!
            no_new_privileges=True,
        )

        report = self.detector.detect(spec, runtime)
        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]
        warnings = [f for f in report.findings
                    if f.severity == DriftSeverity.WARNING]
        info = [f for f in report.findings
                if f.severity == DriftSeverity.INFO]

        self.assertEqual(len(critical), 0)
        self.assertEqual(len(warnings), 0)
        self.assertTrue(len(info) >= 1)  # At least rootfs + seccomp INFO

    # ── Test: WARNING — unexpected capability ──────────────────────

    def test_warning_unexpected_capability(self):
        """Runtime has SYS_PTRACE which was not requested in the spec."""
        spec = SpecSecurityState(
            container_name="cap-drift",
            pod_name="drift-pod",
            namespace="default",
            capabilities_add=[],
            capabilities_drop=[],
        )
        runtime = RuntimeSecurityState(
            container_id="cap001",
            container_name="cap-drift",
            uid=1000,
            capabilities_effective=list(DEFAULT_CAPABILITIES) + ["CAP_SYS_PTRACE"],
            root_readonly=False,
            no_new_privileges=False,
        )

        report = self.detector.detect(spec, runtime)
        warnings = [f for f in report.findings
                    if f.severity == DriftSeverity.WARNING]

        ptrace_findings = [f for f in warnings
                          if "SYS_PTRACE" in f.actual_value]
        self.assertEqual(len(ptrace_findings), 1)

    # ── Test: Full integration with fixture files ──────────────────

    def test_integration_secure_spec_vs_secure_runtime(self):
        """End-to-end: secure pod spec matched against secure runtime fixture."""
        pod = {
            "metadata": {"name": "secure-pod", "namespace": "default"},
            "spec": {
                "securityContext": {
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "good-container",
                    "securityContext": {
                        "runAsUser": 1000,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }],
            },
        }

        spec_states = extract_spec_states(pod)
        runtime_data = load_fixture("crictl_inspect_secure.json")
        runtime_state = parse_crictl_json(runtime_data)

        report = self.detector.detect(spec_states[0], runtime_state)

        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]
        self.assertEqual(len(critical), 0,
                         f"Secure pod should have no critical drift: "
                         f"{[f.description for f in critical]}")

    def test_integration_secure_spec_vs_drifted_runtime(self):
        """End-to-end: secure pod spec against a runtime where
        seccomp was stripped — should produce CRITICAL."""
        pod = {
            "metadata": {"name": "drift-pod", "namespace": "default"},
            "spec": {
                "securityContext": {
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "drifted-container",
                    "securityContext": {
                        "runAsUser": 1000,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }],
            },
        }

        spec_states = extract_spec_states(pod)
        runtime_data = load_fixture("crictl_inspect_seccomp_drift.json")
        runtime_state = parse_crictl_json(runtime_data)

        report = self.detector.detect(spec_states[0], runtime_state)

        critical = [f for f in report.findings
                    if f.severity == DriftSeverity.CRITICAL]
        self.assertTrue(len(critical) >= 1)
        self.assertTrue(any(
            f.field_name == "seccompProfile" for f in critical
        ))

    # ── Test: Report serialization ─────────────────────────────────

    def test_report_to_dict(self):
        """Verify DriftReport serialization works."""
        spec = SpecSecurityState(
            container_name="test",
            pod_name="test-pod",
            namespace="default",
            capabilities_drop=["ALL"],
            seccomp_profile_type="RuntimeDefault",
        )
        runtime = RuntimeSecurityState(
            container_id="test123",
            container_name="test",
            uid=1000,
            capabilities_effective=[],
            seccomp_profile=None,
            root_readonly=True,
        )

        report = self.detector.detect(spec, runtime)
        d = report.to_dict()

        self.assertIn("pod", d)
        self.assertIn("findings", d)
        self.assertIn("critical", d)
        self.assertIsInstance(d["findings"], list)


# ═══════════════════════════════════════════════════════════════════
#  Policy Engine Tests (Layer 1 — existing functionality)
# ═══════════════════════════════════════════════════════════════════


class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        import tempfile
        policy = """
checks:
  - id: "privileged_container"
    description: "Container should not run in privileged mode"
    severity: "high"
  - id: "root_container"
    description: "Container should not run as root user"
    severity: "high"
  - id: "host_network"
    description: "Pod should not use host network"
    severity: "medium"
"""
        self.temp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        self.temp.write(policy)
        self.temp.close()

        from src.policy_engine import PolicyEngine
        self.engine = PolicyEngine(self.temp.name)

    def tearDown(self):
        os.unlink(self.temp.name)

    def test_detect_privileged(self):
        pod = {
            "metadata": {"name": "p", "namespace": "d"},
            "spec": {"containers": [
                {"name": "c", "securityContext": {"privileged": True}}
            ]},
        }
        v = self.engine.check_pod(pod)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["check_id"], "privileged_container")

    def test_secure_pod_passes(self):
        pod = {
            "metadata": {"name": "s", "namespace": "d"},
            "spec": {
                "hostNetwork": False,
                "securityContext": {"runAsNonRoot": True},
                "containers": [{"name": "c", "securityContext": {
                    "runAsUser": 1000, "runAsNonRoot": True
                }}],
            },
        }
        v = self.engine.check_pod(pod)
        self.assertEqual(len(v), 0)


if __name__ == "__main__":
    unittest.main()
