import json
import logging
from typing import List, Dict

class AlertManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def send_alerts(self, violations: List[Dict]):
        """Send alerts for security violations"""
        # Simple implementation: log to stdout and file
        self._log_to_stdout(violations)
        self._log_to_file(violations)
        
        # Could be extended to send to:
        # - Slack
        # - Email
        # - Webhook
        # - SIEM system
    
    def _log_to_stdout(self, violations: List[Dict]):
        """Log violations to stdout in structured format"""
        for violation in violations:
            print(json.dumps({
                'type': 'security_violation',
                **violation
            }))
    
    def _log_to_file(self, violations: List[Dict]):
        """Log violations to a file"""
        try:
            with open('/var/log/k8s-psa-violations.log', 'a') as f:
                for violation in violations:
                    f.write(json.dumps(violation) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write to log file: {e}")