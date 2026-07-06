"""
Spec Extractor — converts a Kubernetes API pod spec dict into
SpecSecurityState objects (one per container).
"""

from typing import List, Dict
from src.models import SpecSecurityState


def extract_spec_states(pod: Dict) -> List[SpecSecurityState]:
    """
    Given a raw pod JSON (from `kubectl get pod -o json`), produce
    a SpecSecurityState for every container in the pod.
    """
    metadata = pod.get("metadata", {})
    pod_name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    spec = pod.get("spec", {})
    pod_sec = spec.get("securityContext", {})

    # Pod-level settings
    host_network = spec.get("hostNetwork", False) or False
    host_pid = spec.get("hostPID", False) or False
    host_ipc = spec.get("hostIPC", False) or False

    # Pod-level seccomp
    seccomp = pod_sec.get("seccompProfile", {})
    seccomp_type = seccomp.get("type", None)
    seccomp_path = seccomp.get("localhostProfile", None)

    # Pod-level user/group
    pod_run_as_user = pod_sec.get("runAsUser", None)
    pod_run_as_group = pod_sec.get("runAsGroup", None)

    states = []
    for container in spec.get("containers", []):
        c_sec = container.get("securityContext", {})
        caps = c_sec.get("capabilities", {})

        # Container-level seccomp overrides pod-level
        c_seccomp = c_sec.get("seccompProfile", {})
        c_seccomp_type = c_seccomp.get("type", seccomp_type)
        c_seccomp_path = c_seccomp.get("localhostProfile", seccomp_path)

        state = SpecSecurityState(
            container_name=container.get("name", "unknown"),
            pod_name=pod_name,
            namespace=namespace,
            privileged=c_sec.get("privileged", False) or False,
            run_as_user=c_sec.get("runAsUser", None),
            run_as_group=c_sec.get("runAsGroup", None),
            read_only_root_filesystem=c_sec.get(
                "readOnlyRootFilesystem", False
            ) or False,
            allow_privilege_escalation=c_sec.get(
                "allowPrivilegeEscalation", None
            ),
            capabilities_add=caps.get("add", []) or [],
            capabilities_drop=caps.get("drop", []) or [],
            seccomp_profile_type=c_seccomp_type,
            seccomp_profile_path=c_seccomp_path,
            host_network=host_network,
            host_pid=host_pid,
            host_ipc=host_ipc,
            pod_run_as_user=pod_run_as_user,
            pod_run_as_group=pod_run_as_group,
        )
        states.append(state)

    return states
