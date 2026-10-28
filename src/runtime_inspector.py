"""
Runtime Inspector — extracts the *actual* security state of running
containers by querying the container runtime directly.

Supports two backends with auto-detection:
  • docker  (for Minikube with Docker driver, Docker Desktop, etc.)
  • crictl  (for containerd / CRI-O clusters — kind, production, etc.)

Auto-detection logic:
  1. Check if /var/run/docker.sock exists → use docker
  2. Check if /var/run/containerd/containerd.sock exists → use crictl
  3. Try `docker version` → use docker
  4. Try `crictl version` → use crictl
  5. Give up and log an error
"""

import subprocess
import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from src.models import RuntimeSecurityState
from src.normalizer import normalize_cap_name

logger = logging.getLogger(__name__)


class RuntimeInspector:
    def __init__(self, backend: str = "auto"):
        if backend == "auto":
            self.backend = self._detect_backend()
        else:
            self.backend = backend
        logger.info(f"RuntimeInspector using backend: {self.backend}")

    @staticmethod
    def _detect_backend() -> str:
        if os.path.exists("/var/run/docker.sock"):
            logger.info("Detected /var/run/docker.sock -> using docker")
            return "docker"
        if os.path.exists("/var/run/containerd/containerd.sock"):
            logger.info("Detected containerd socket -> using crictl")
            return "crictl"
        for cmd, backend in [("docker", "docker"), ("crictl", "crictl")]:
            try:
                r = subprocess.run([cmd, "version"], capture_output=True, timeout=5, check=False)
                if r.returncode == 0:
                    logger.info(f"{cmd} CLI available -> using {backend}")
                    return backend
            except FileNotFoundError:
                continue
        logger.error("No container runtime detected! Layer 2 will not work.")
        return "none"

    @property
    def is_available(self) -> bool:
        return self.backend != "none"

    def list_containers(self) -> List[Tuple[str, str]]:
        if self.backend == "docker":
            return self._list_docker()
        elif self.backend == "crictl":
            return self._list_crictl()
        return []

    def _list_docker(self) -> List[Tuple[str, str]]:
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}}"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            ids = [cid.strip() for cid in result.stdout.strip().split("\n") if cid.strip()]
            return [(cid, cid) for cid in ids]
        except Exception as e:
            logger.error(f"docker ps failed: {e}")
            return []

    def _list_crictl(self) -> List[Tuple[str, str]]:
        try:
            result = subprocess.run(
                ["crictl", "ps", "-o", "json"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            data = json.loads(result.stdout)
            return [(c.get("id", ""), c.get("podSandboxId", "")) for c in data.get("containers", [])]
        except Exception as e:
            logger.error(f"crictl ps failed: {e}")
            return []

    def inspect_container(self, container_id: str, pod_id: str = "") -> Optional[RuntimeSecurityState]:
        if self.backend == "docker":
            return self._inspect_docker(container_id)
        elif self.backend == "crictl":
            return self._inspect_crictl(container_id, pod_id)
        return None

    # ══════════════════════════════════════════════════════════════
    #  DOCKER BACKEND
    # ══════════════════════════════════════════════════════════════

    def _inspect_docker(self, container_id: str) -> Optional[RuntimeSecurityState]:
        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True, text=True, timeout=15, check=True,
            )
            data = json.loads(result.stdout)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            else:
                return None
        except Exception as e:
            logger.error(f"docker inspect {container_id[:12]} failed: {e}")
            return None
        return self._parse_docker_inspect(data, container_id)

    def _parse_docker_inspect(self, data: dict, container_id: str) -> RuntimeSecurityState:
        host_config = data.get("HostConfig", {})
        config = data.get("Config", {})
        state_info = data.get("State", {})

        # Container name: prefer Kubernetes label
        labels = config.get("Labels", {})
        container_name = labels.get("io.kubernetes.container.name", "")
        if not container_name:
            container_name = data.get("Name", "").lstrip("/")

        # User ID
        user_str = config.get("User", "")
        uid, gid = 0, 0
        if user_str:
            parts = user_str.split(":")
            try:
                uid = int(parts[0])
                gid = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                uid, gid = -1, -1  # Name-based user, can't resolve

        # Capabilities — Docker stores add/drop, we compute effective
        cap_add = host_config.get("CapAdd") or []
        cap_drop = host_config.get("CapDrop") or []
        is_privileged = host_config.get("Privileged", False)

        if is_privileged:
            from src.normalizer import ALL_CAPABILITIES
            effective_caps = sorted(ALL_CAPABILITIES)
        else:
            from src.normalizer import compute_expected_capabilities
            effective_caps = sorted(compute_expected_capabilities(cap_add, cap_drop))

        effective_caps_normalized = [normalize_cap_name(c) for c in effective_caps]

        # Seccomp
        security_opts = host_config.get("SecurityOpt") or []
        seccomp_profile = None
        for opt in security_opts:
            if isinstance(opt, str) and "seccomp=" in opt:
                profile_str = opt.split("seccomp=", 1)[1]
                if profile_str != "unconfined":
                    seccomp_profile = {"type": "applied", "value": profile_str}
        if is_privileged:
            seccomp_profile = None

        # No new privileges
        no_new_privs = False
        for opt in security_opts:
            if isinstance(opt, str) and "no-new-privileges" in opt:
                no_new_privs = True

        # Namespaces
        pid_mode = host_config.get("PidMode", "")
        network_mode = host_config.get("NetworkMode", "")
        ipc_mode = host_config.get("IpcMode", "")
        ns_pid = 2 if pid_mode == "host" else 0
        ns_network = 2 if network_mode == "host" else 0
        ns_ipc = 2 if ipc_mode == "host" else 0

        # Masked/Readonly paths
        masked_paths = host_config.get("MaskedPaths") or []
        readonly_paths = host_config.get("ReadonlyPaths") or []

        return RuntimeSecurityState(
            container_id=container_id,
            container_name=container_name,
            pid=state_info.get("Pid"),
            uid=uid,
            gid=gid,
            capabilities_bounding=effective_caps_normalized,
            capabilities_effective=effective_caps_normalized,
            capabilities_permitted=effective_caps_normalized,
            seccomp_profile=seccomp_profile,
            root_readonly=host_config.get("ReadonlyRootfs", False),
            no_new_privileges=no_new_privs,
            masked_paths=masked_paths,
            readonly_paths=readonly_paths,
            namespace_pid=ns_pid,
            namespace_network=ns_network,
            namespace_ipc=ns_ipc,
        )

    # ══════════════════════════════════════════════════════════════
    #  CRICTL BACKEND
    # ══════════════════════════════════════════════════════════════

    def _inspect_crictl(self, container_id: str, pod_id: str) -> Optional[RuntimeSecurityState]:
        try:
            result = subprocess.run(
                ["crictl", "inspect", container_id],
                capture_output=True, text=True, timeout=15, check=True,
            )
            data = json.loads(result.stdout)
        except Exception as e:
            logger.error(f"crictl inspect {container_id[:12]} failed: {e}")
            return None
        return self._parse_crictl_data(data, container_id, pod_id)

    def _parse_crictl_data(self, data: dict, container_id: str, pod_id: str) -> Optional[RuntimeSecurityState]:
        info = data.get("info", {})
        runtime_spec = info.get("runtimeSpec", {})
        if not runtime_spec:
            logger.warning(f"No runtimeSpec for {container_id[:12]}")
            return self._parse_crictl_config_fallback(data, container_id, pod_id)

        process = runtime_spec.get("process", {})
        user = process.get("user", {})
        caps = process.get("capabilities", {})
        linux = runtime_spec.get("linux", {})
        root = runtime_spec.get("root", {})
        status = data.get("status", {})
        container_name = status.get("metadata", {}).get("name", "unknown")

        ns_pid, ns_net, ns_ipc = None, None, None
        if pod_id:
            ns_pid, ns_net, ns_ipc = self._get_pod_namespaces(pod_id)

        return RuntimeSecurityState(
            container_id=container_id,
            container_name=container_name,
            pid=info.get("pid"),
            uid=user.get("uid", 0),
            gid=user.get("gid", 0),
            capabilities_bounding=[normalize_cap_name(c) for c in caps.get("bounding", [])],
            capabilities_effective=[normalize_cap_name(c) for c in caps.get("effective", [])],
            capabilities_permitted=[normalize_cap_name(c) for c in caps.get("permitted", [])],
            seccomp_profile=linux.get("seccomp", None),
            root_readonly=root.get("readonly", False),
            no_new_privileges=process.get("noNewPrivileges", False),
            masked_paths=linux.get("maskedPaths", []),
            readonly_paths=linux.get("readonlyPaths", []),
            namespace_pid=ns_pid,
            namespace_network=ns_net,
            namespace_ipc=ns_ipc,
        )

    def _parse_crictl_config_fallback(self, data, container_id, pod_id):
        info = data.get("info", {})
        config = info.get("config", {})
        sec_ctx = config.get("linux", {}).get("security_context", {})
        status = data.get("status", {})
        container_name = status.get("metadata", {}).get("name", "unknown")
        caps = sec_ctx.get("capabilities", {})
        seccomp = sec_ctx.get("seccomp", {})
        seccomp_val = seccomp if seccomp.get("profile_type") else None
        ns_pid, ns_net, ns_ipc = (None, None, None)
        if pod_id:
            ns_pid, ns_net, ns_ipc = self._get_pod_namespaces(pod_id)
        return RuntimeSecurityState(
            container_id=container_id, container_name=container_name,
            pid=info.get("pid"),
            uid=sec_ctx.get("run_as_user", {}).get("value", 0),
            gid=sec_ctx.get("run_as_group", {}).get("value", 0),
            capabilities_bounding=[normalize_cap_name(c) for c in caps.get("add_capabilities", [])],
            capabilities_effective=[normalize_cap_name(c) for c in caps.get("add_capabilities", [])],
            capabilities_permitted=[normalize_cap_name(c) for c in caps.get("add_capabilities", [])],
            seccomp_profile=seccomp_val,
            root_readonly=sec_ctx.get("readonly_rootfs", False),
            no_new_privileges=sec_ctx.get("no_new_privs", False),
            masked_paths=[], readonly_paths=[],
            namespace_pid=ns_pid, namespace_network=ns_net, namespace_ipc=ns_ipc,
        )

    def _get_pod_namespaces(self, pod_id):
        try:
            result = subprocess.run(
                ["crictl", "inspectp", pod_id],
                capture_output=True, text=True, timeout=15, check=True,
            )
            data = json.loads(result.stdout)
            ns = data.get("info", {}).get("config", {}).get("linux", {}).get("security_context", {}).get("namespace_options", {})
            return (ns.get("pid", 0), ns.get("network", 0), ns.get("ipc", 0))
        except Exception as e:
            logger.debug(f"crictl inspectp failed: {e}")
            return None, None, None


# ── Convenience for unit testing ──────────────────────────────────

def parse_crictl_json(container_json, pod_json=None):
    inspector = RuntimeInspector.__new__(RuntimeInspector)
    inspector.backend = "crictl"
    container_id = container_json.get("status", {}).get("id", "test-id")
    pod_id = pod_json.get("status", {}).get("id", "") if pod_json else ""
    state = inspector._parse_crictl_data(container_json, container_id, pod_id)
    if pod_json and state:
        ns = pod_json.get("info", {}).get("config", {}).get("linux", {}).get("security_context", {}).get("namespace_options", {})
        state.namespace_pid = ns.get("pid", 0)
        state.namespace_network = ns.get("network", 0)
        state.namespace_ipc = ns.get("ipc", 0)
    return state


def parse_docker_json(inspect_json):
    inspector = RuntimeInspector.__new__(RuntimeInspector)
    inspector.backend = "docker"
    container_id = inspect_json.get("Id", "test-id")
    return inspector._parse_docker_inspect(inspect_json, container_id)
