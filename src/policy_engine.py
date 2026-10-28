"""
Policy Engine — checks pod specifications against configurable security
policies.  This is the *spec-level* checker (Layer 1).

The Drift Detector (Layer 2) then compares these declarations against
the actual runtime state.
"""

import yaml
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class PolicyEngine:
    def __init__(self, policy_file: str = "policies/default.yaml"):
        self.policies = self._load_policies(policy_file)
        self.checks = {
            "privileged_container": self._check_privileged,
            "root_container": self._check_root_user,
            "host_network": self._check_host_network,
            "host_pid": self._check_host_pid,
            "host_ipc": self._check_host_ipc,
            "seccomp_profile": self._check_seccomp,
            "capabilities": self._check_capabilities,
            "read_only_root": self._check_readonly_root,
        }

    def _load_policies(self, policy_file: str) -> Dict:
        try:
            with open(policy_file, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Policy file {policy_file} not found, using empty")
            return {"checks": []}

    def check_pod(self, pod_info: Dict) -> List[Dict]:
        violations = []
        for check_config in self.policies.get("checks", []):
            check_id = check_config["id"]
            if check_id in self.checks:
                result = self.checks[check_id](pod_info)
                if not result["passed"]:
                    violations.append({
                        "check_id": check_id,
                        "description": check_config["description"],
                        "severity": check_config["severity"],
                        "message": result["message"],
                        "pod": pod_info["metadata"]["name"],
                        "namespace": pod_info["metadata"]["namespace"],
                    })
        return violations

    def _check_privileged(self, pod_info: Dict) -> Dict:
        for c in pod_info.get("spec", {}).get("containers", []):
            sc = c.get("securityContext", {})
            if sc.get("privileged") is True:
                return {"passed": False,
                        "message": f"Container {c['name']} is running in privileged mode"}
        return {"passed": True, "message": ""}

    def _check_root_user(self, pod_info: Dict) -> Dict:
        pod_ctx = pod_info.get("spec", {}).get("securityContext", {})
        for c in pod_info.get("spec", {}).get("containers", []):
            ctx = c.get("securityContext", {})
            if ctx.get("runAsNonRoot") is False:
                return {"passed": False,
                        "message": f"Container {c['name']} explicitly allows running as root"}
            if ctx.get("runAsUser") == 0:
                return {"passed": False,
                        "message": f"Container {c['name']} runs as UID 0 (root)"}
            if pod_ctx.get("runAsUser") == 0 and ctx.get("runAsUser") is None:
                return {"passed": False,
                        "message": f"Container {c['name']} inherits root UID from pod"}
        return {"passed": True, "message": ""}

    def _check_host_network(self, pod_info: Dict) -> Dict:
        if pod_info.get("spec", {}).get("hostNetwork") is True:
            return {"passed": False, "message": "Pod uses host network namespace"}
        return {"passed": True, "message": ""}

    def _check_host_pid(self, pod_info: Dict) -> Dict:
        if pod_info.get("spec", {}).get("hostPID") is True:
            return {"passed": False, "message": "Pod uses host PID namespace"}
        return {"passed": True, "message": ""}

    def _check_host_ipc(self, pod_info: Dict) -> Dict:
        if pod_info.get("spec", {}).get("hostIPC") is True:
            return {"passed": False, "message": "Pod uses host IPC namespace"}
        return {"passed": True, "message": ""}

    def _check_seccomp(self, pod_info: Dict) -> Dict:
        pod_ctx = pod_info.get("spec", {}).get("securityContext", {})
        profile = pod_ctx.get("seccompProfile", {}).get("type", "")
        if profile not in ("RuntimeDefault", "Localhost"):
            return {"passed": False,
                    "message": f"No seccomp profile or unsafe profile: {profile}"}
        return {"passed": True, "message": ""}

    def _check_capabilities(self, pod_info: Dict) -> Dict:
        dangerous = {"NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"}
        for c in pod_info.get("spec", {}).get("containers", []):
            caps = c.get("securityContext", {}).get("capabilities", {})
            for cap in caps.get("add", []):
                if cap in dangerous:
                    return {"passed": False,
                            "message": f"Container {c['name']} has dangerous capability: {cap}"}
        return {"passed": True, "message": ""}

    def _check_readonly_root(self, pod_info: Dict) -> Dict:
        for c in pod_info.get("spec", {}).get("containers", []):
            ctx = c.get("securityContext", {})
            if ctx.get("readOnlyRootFilesystem") is not True:
                return {"passed": False,
                        "message": f"Container {c['name']} root filesystem is not read-only"}
        return {"passed": True, "message": ""}
