import time
import logging
import json
from datetime import datetime
from src.pod_scanner import PodScanner
from src.policy_engine import PolicyEngine
from src.alert_manager import AlertManager

class K8sPSA:
    def __init__(self, node_name: str, scan_interval: int = 300):
        self.node_name = node_name
        self.scan_interval = scan_interval
        self.pod_scanner = PodScanner(node_name)
        self.policy_engine = PolicyEngine()
        self.alert_manager = AlertManager()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def scan(self):
        """Perform a single security scan"""
        self.logger.info(f"Starting security scan on node: {self.node_name}")
        
        # Get all pods on this node
        pods = self.pod_scanner.get_pods_on_node()
        self.logger.info(f"Found {len(pods)} pods on node {self.node_name}")
        
        all_violations = []
        
        # Check each pod
        for pod in pods:
            pod_name = pod['metadata']['name']
            namespace = pod['metadata']['namespace']
            
            self.logger.debug(f"Scanning pod: {namespace}/{pod_name}")
            
            # Run security checks
            violations = self.policy_engine.check_pod(pod)
            
            if violations:
                all_violations.extend(violations)
                self.logger.warning(f"Found {len(violations)} violations in pod {namespace}/{pod_name}")
                
                # Log each violation
                for violation in violations:
                    self.logger.warning(
                        f"Violation: {violation['check_id']} - "
                        f"Severity: {violation['severity']} - "
                        f"Message: {violation['message']}"
                    )
        
        # Send alerts if any violations found
        if all_violations:
            self.alert_manager.send_alerts(all_violations)
        
        # Generate report
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'node': self.node_name,
            'pods_scanned': len(pods),
            'violations_found': len(all_violations),
            'violations': all_violations
        }
        
        # Print summary report as JSON for easy parsing
        print(json.dumps(report, indent=2))
        
        return report
    
    def run_continuous(self):
        """Run continuous scanning"""
        self.logger.info(f"Starting continuous security monitoring on node: {self.node_name}")
        
        while True:
            try:
                self.scan()
                self.logger.info(f"Sleeping for {self.scan_interval} seconds...")
                time.sleep(self.scan_interval)
            except KeyboardInterrupt:
                self.logger.info("Received interrupt, shutting down...")
                break
            except Exception as e:
                self.logger.error(f"Error during scan: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == "__main__":
    import os
    
    # Get node name from environment or hostname
    node_name = os.getenv('NODE_NAME', os.uname().nodename)
    scan_interval = int(os.getenv('SCAN_INTERVAL', '300'))  # Default 5 minutes
    
    auditor = K8sPSA(node_name, scan_interval)
    
    # Run once if INTERACTIVE mode, otherwise run continuously
    if os.getenv('INTERACTIVE', 'false').lower() == 'true':
        auditor.scan()
    else:
        auditor.run_continuous()