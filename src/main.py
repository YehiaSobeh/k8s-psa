"""
k8s-psa — Kubernetes Pod Security Auditor (main entry point)

Writes all findings as NDJSON to /data/ for the dashboard to read.
"""

import os
import time
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict

from src.pod_scanner import PodScanner
from src.policy_engine import PolicyEngine
from src.alert_manager import AlertManager
from src.runtime_inspector import RuntimeInspector
from src.spec_extractor import extract_spec_states
from src.drift_detector import DriftDetector
from src.models import DriftReport


class K8sPSA:
    def __init__(
        self,
        node_name: str,
        scan_interval: int = 300,
        policy_file: str = "policies/default.yaml",
        enable_drift: bool = True,
        runtime_backend: str = "auto",
        data_dir: str = "/data",
    ):
        self.node_name = node_name
        self.scan_interval = scan_interval
        self.enable_drift = enable_drift

        self.pod_scanner = PodScanner(node_name)
        self.policy_engine = PolicyEngine(policy_file)
        self.alert_manager = AlertManager(data_dir=data_dir)
        self.drift_detector = DriftDetector()

        if enable_drift:
            self.runtime_inspector = RuntimeInspector(backend=runtime_backend)
        else:
            self.runtime_inspector = None

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger(__name__)

    def scan(self) -> Dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        self.logger.info(f"Starting security scan on node: {self.node_name}")

        pods = self.pod_scanner.get_pods_on_node()
        self.logger.info(f"Found {len(pods)} pods on node {self.node_name}")

        # Layer 1
        all_violations = []
        for pod in pods:
            violations = self.policy_engine.check_pod(pod)
            if violations:
                all_violations.extend(violations)
                ns = pod["metadata"]["namespace"]
                name = pod["metadata"]["name"]
                self.logger.warning(
                    f"[Layer 1] {len(violations)} spec violations in {ns}/{name}"
                )

        if all_violations:
            self.alert_manager.send_spec_alerts(all_violations)

        # Layer 2
        all_drift_reports: List[DriftReport] = []
        if self.enable_drift and self.runtime_inspector:
            all_drift_reports = self._run_drift_detection(pods)

        if all_drift_reports:
            self.alert_manager.send_drift_alerts(all_drift_reports)

        # Scan summary → /data/scans.jsonl
        summary = {
            "timestamp": timestamp,
            "node": self.node_name,
            "pods_scanned": len(pods),
            "layer1_violations": len(all_violations),
            "layer2_drift_reports": len(all_drift_reports),
            "layer2_critical": sum(1 for r in all_drift_reports if r.has_critical),
            "layer2_warning": sum(1 for r in all_drift_reports if r.has_warning),
            "layer2_total_findings": sum(r.finding_count for r in all_drift_reports),
        }
        self.alert_manager.write_scan_summary(summary)
        return summary

    def _run_drift_detection(self, pods: List[Dict]) -> List[DriftReport]:
        self.logger.info("[Layer 2] Starting drift detection...")
        containers = self.runtime_inspector.list_containers()
        self.logger.info(f"[Layer 2] Found {len(containers)} running containers")

        runtime_states = {}
        for cid, pod_id in containers:
            state = self.runtime_inspector.inspect_container(cid, pod_id)
            if state:
                runtime_states[state.container_name] = state

        reports = []
        for pod in pods:
            for spec_state in extract_spec_states(pod):
                runtime_state = runtime_states.get(spec_state.container_name)
                if not runtime_state:
                    continue
                report = self.drift_detector.detect(spec_state, runtime_state)
                report.scan_timestamp = datetime.now(timezone.utc).isoformat()
                reports.append(report)

                if report.has_critical:
                    self.logger.warning(
                        f"[Layer 2] CRITICAL drift in "
                        f"{spec_state.namespace}/{spec_state.pod_name}/"
                        f"{spec_state.container_name}: {report.finding_count} findings"
                    )

        self.logger.info(
            f"[Layer 2] Complete: {sum(r.finding_count for r in reports)} "
            f"findings across {len(reports)} containers"
        )
        return reports

    def run_continuous(self):
        self.logger.info(
            f"Starting continuous monitoring on {self.node_name} "
            f"(interval={self.scan_interval}s)"
        )
        while True:
            try:
                self.scan()
                self.logger.info(f"Sleeping {self.scan_interval}s...")
                time.sleep(self.scan_interval)
            except KeyboardInterrupt:
                self.logger.info("Shutting down...")
                break
            except Exception as e:
                self.logger.error(f"Scan error: {e}")
                time.sleep(60)


if __name__ == "__main__":
    node_name = os.getenv("NODE_NAME", os.uname().nodename)
    scan_interval = int(os.getenv("SCAN_INTERVAL", "60"))
    enable_drift = os.getenv("ENABLE_DRIFT", "true").lower() == "true"
    runtime_backend = os.getenv("RUNTIME_BACKEND", "auto")
    data_dir = os.getenv("DATA_DIR", "/data")

    auditor = K8sPSA(
        node_name=node_name,
        scan_interval=scan_interval,
        enable_drift=enable_drift,
        runtime_backend=runtime_backend,
        data_dir=data_dir,
    )

    if os.getenv("INTERACTIVE", "false").lower() == "true":
        auditor.scan()
    else:
        auditor.run_continuous()
