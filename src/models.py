"""
Data models representing container security state at two layers:
  1. SpecSecurityState  — what the Kubernetes API declares
  2. RuntimeSecurityState — what the container runtime actually configured
  3. DriftReport — the result of comparing the two
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class DriftSeverity(Enum):
    """Classification of a spec-vs-runtime divergence."""
    INFO = "info"            # Benign default added by runtime
    WARNING = "warning"      # Unexpected addition not in spec
    CRITICAL = "critical"    # Declared restriction missing at runtime


class DriftCategory(Enum):
    """What kind of divergence was detected."""
    BENIGN_DEFAULT = "benign_default"
    UNEXPECTED_ADDITION = "unexpected_addition"
    SECURITY_DEGRADATION = "security_degradation"
    USER_MISMATCH = "user_mismatch"
    SECCOMP_MISMATCH = "seccomp_mismatch"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROOTFS_MISMATCH = "rootfs_mismatch"
    NAMESPACE_MISMATCH = "namespace_mismatch"


@dataclass
class SpecSecurityState:
    """Security properties as declared in the Kubernetes pod spec."""
    container_name: str
    pod_name: str
    namespace: str

    # Container-level securityContext
    privileged: bool = False
    run_as_user: Optional[int] = None
    run_as_group: Optional[int] = None
    read_only_root_filesystem: bool = False
    allow_privilege_escalation: Optional[bool] = None
    capabilities_add: List[str] = field(default_factory=list)
    capabilities_drop: List[str] = field(default_factory=list)

    # Pod-level securityContext
    seccomp_profile_type: Optional[str] = None  # Unconfined, RuntimeDefault, Localhost
    seccomp_profile_path: Optional[str] = None
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False

    # Pod-level run_as_user (inherited if container doesn't override)
    pod_run_as_user: Optional[int] = None
    pod_run_as_group: Optional[int] = None


@dataclass
class RuntimeSecurityState:
    """Security properties as reported by the container runtime (crictl/docker)."""
    container_id: str
    container_name: str
    pid: Optional[int] = None

    # From OCI runtimeSpec
    uid: Optional[int] = None
    gid: Optional[int] = None
    capabilities_bounding: List[str] = field(default_factory=list)
    capabilities_effective: List[str] = field(default_factory=list)
    capabilities_permitted: List[str] = field(default_factory=list)
    seccomp_profile: Optional[dict] = None    # None = unconfined
    root_readonly: bool = False
    no_new_privileges: bool = False
    masked_paths: List[str] = field(default_factory=list)
    readonly_paths: List[str] = field(default_factory=list)

    # Namespace options (from crictl inspectp)
    namespace_pid: Optional[int] = None       # 0=pod, 2=host
    namespace_network: Optional[int] = None
    namespace_ipc: Optional[int] = None

    # Privileged inference
    @property
    def is_effectively_privileged(self) -> bool:
        """Infer privileged mode from constituent OCI settings."""
        has_all_caps = "CAP_SYS_ADMIN" in self.capabilities_bounding \
            and "CAP_NET_ADMIN" in self.capabilities_bounding \
            and len(self.capabilities_bounding) > 30
        no_seccomp = self.seccomp_profile is None
        no_masked = len(self.masked_paths) == 0
        return has_all_caps and no_seccomp and no_masked


@dataclass
class DriftFinding:
    """A single divergence between declared and actual security."""
    field_name: str
    description: str
    severity: DriftSeverity
    category: DriftCategory
    declared_value: str
    actual_value: str


@dataclass
class DriftReport:
    """Complete drift analysis for one container."""
    pod_name: str
    namespace: str
    container_name: str
    container_id: str
    findings: List[DriftFinding] = field(default_factory=list)
    scan_timestamp: str = ""

    @property
    def has_critical(self) -> bool:
        return any(f.severity == DriftSeverity.CRITICAL for f in self.findings)

    @property
    def has_warning(self) -> bool:
        return any(f.severity == DriftSeverity.WARNING for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict:
        return {
            "pod": self.pod_name,
            "namespace": self.namespace,
            "container": self.container_name,
            "container_id": self.container_id,
            "scan_timestamp": self.scan_timestamp,
            "total_findings": self.finding_count,
            "critical": sum(1 for f in self.findings if f.severity == DriftSeverity.CRITICAL),
            "warning": sum(1 for f in self.findings if f.severity == DriftSeverity.WARNING),
            "info": sum(1 for f in self.findings if f.severity == DriftSeverity.INFO),
            "findings": [
                {
                    "field": f.field_name,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "declared": f.declared_value,
                    "actual": f.actual_value,
                }
                for f in self.findings
            ],
        }
