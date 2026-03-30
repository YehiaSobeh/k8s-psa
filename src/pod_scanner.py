import subprocess
import json
import logging
from typing import List, Dict

class PodScanner:
    def __init__(self, node_name: str):
        self.node_name = node_name
        self.logger = logging.getLogger(__name__)
    
    def get_pods_on_node(self) -> List[Dict]:
        """Get all pods running on this node using kubectl"""
        try:
            # Using kubectl for simplicity
            cmd = [
                'kubectl', 'get', 'pods',
                '--all-namespaces',
                '-o', 'json',
                '--field-selector', f'spec.nodeName={self.node_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            pods_data = json.loads(result.stdout)
            return pods_data.get('items', [])
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get pods: {e.stderr}")
            return []
        except Exception as e:
            self.logger.error(f"Error getting pods: {e}")
            return []
    
    def get_pod_details(self, pod_name: str, namespace: str) -> Dict:
        """Get detailed pod information"""
        try:
            cmd = [
                'kubectl', 'get', 'pod', pod_name,
                '-n', namespace,
                '-o', 'json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
            
        except Exception as e:
            self.logger.error(f"Failed to get pod details: {e}")
            return {}