"""
Alert Manager — writes all findings as NDJSON (one JSON object per line)
to a shared volume that the dashboard pod reads.

Output paths:
  /data/findings.jsonl  — every individual finding (spec + drift)
  /data/scans.jsonl     — one summary per scan cycle
  stdout                — same data (for kubectl logs)
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import List, Dict

from src.models import DriftReport

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, data_dir: str = "/data"):
        self.data_dir = data_dir
        self.findings_file = os.path.join(data_dir, "findings.jsonl")
        self.scans_file = os.path.join(data_dir, "scans.jsonl")
        os.makedirs(data_dir, exist_ok=True)

    def send_spec_alerts(self, violations: List[Dict]):
        """Write spec-level violations."""
        ts = datetime.now(timezone.utc).isoformat()
        for v in violations:
            record = {
                "type": "spec_violation",
                "timestamp": ts,
                **v,
            }
            self._emit(record)

    def send_drift_alerts(self, reports: List[DriftReport]):
        """Write drift findings."""
        ts = datetime.now(timezone.utc).isoformat()
        for report in reports:
            for finding in report.findings:
                record = {
                    "type": "drift_finding",
                    "timestamp": ts,
                    "pod": report.pod_name,
                    "namespace": report.namespace,
                    "container": report.container_name,
                    "container_id": report.container_id[:12],
                    "field": finding.field_name,
                    "severity": finding.severity.value,
                    "category": finding.category.value,
                    "description": finding.description,
                    "declared": finding.declared_value,
                    "actual": finding.actual_value,
                }
                self._emit(record)

    def write_scan_summary(self, summary: Dict):
        """Write one scan cycle summary."""
        line = json.dumps(summary)
        print(line)
        try:
            with open(self.scans_file, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write scan summary: {e}")

    def _emit(self, record: Dict):
        """Write one record to stdout and to the shared file."""
        line = json.dumps(record)
        print(line)
        try:
            with open(self.findings_file, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write finding: {e}")
