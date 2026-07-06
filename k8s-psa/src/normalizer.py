"""
Normalizer for Kubernetes and OCI security settings.

The container runtime adds default Linux capabilities to containers that
do not explicitly drop them.  The kubelet may also apply a default seccomp
profile.  This module defines those defaults so the drift detector can
distinguish *expected* divergences from *unexpected* ones.

Reference: OCI Runtime Spec + Docker/containerd default capability set.
"""

from typing import List, Set

# ── Default capabilities granted by containerd / Docker ────────────────────
# These are the capabilities that the runtime adds to every unprivileged
# container unless the pod spec explicitly drops them.
DEFAULT_CAPABILITIES: Set[str] = {
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
}

# ── All Linux capabilities (kernel 5.x) ───────────────────────────────────
# Used to check if a container has been granted ALL capabilities
# (indicator of privileged mode).
ALL_CAPABILITIES: Set[str] = {
    "CAP_AUDIT_CONTROL", "CAP_AUDIT_READ", "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER", "CAP_FSETID", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_KILL", "CAP_LEASE", "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_MKNOD",
    "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_RAW", "CAP_PERFMON", "CAP_SETFCAP", "CAP_SETGID",
    "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT", "CAP_SYS_CHROOT", "CAP_SYS_MODULE",
    "CAP_SYS_NICE", "CAP_SYS_PACCT", "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG", "CAP_SYSLOG", "CAP_WAKE_ALARM",
}

# ── Default masked paths in non-privileged containers ──────────────────────
DEFAULT_MASKED_PATHS: List[str] = [
    "/proc/asound",
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
]


def normalize_cap_name(cap: str) -> str:
    """Ensure capability name has the CAP_ prefix and is uppercase."""
    cap = cap.upper().strip()
    if not cap.startswith("CAP_"):
        cap = "CAP_" + cap
    return cap


def compute_expected_capabilities(
    caps_add: List[str],
    caps_drop: List[str],
) -> Set[str]:
    """
    Given a pod spec's capabilities.add and capabilities.drop lists,
    compute the set of capabilities the runtime is *expected* to grant.

    Logic:
      - Start with DEFAULT_CAPABILITIES.
      - Remove anything in caps_drop.
      - Add anything in caps_add.
      - Special case: if caps_drop contains "ALL", start from empty set,
        then add caps_add.
    """
    add_set = {normalize_cap_name(c) for c in caps_add}
    drop_set = {normalize_cap_name(c) for c in caps_drop}

    if "CAP_ALL" in drop_set or "ALL" in {c.upper() for c in caps_drop}:
        # Drop ALL means start from nothing, only add explicit additions
        expected = set(add_set)
    else:
        expected = set(DEFAULT_CAPABILITIES)
        expected -= drop_set
        expected |= add_set

    return expected


def is_default_capability(cap: str) -> bool:
    """Check if a capability is part of the default runtime set."""
    return normalize_cap_name(cap) in DEFAULT_CAPABILITIES
