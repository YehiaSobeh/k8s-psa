import subprocess
import json
import logging

class RuntimeInspector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def inspect_container_runtime(self, container_id: str) -> Dict:
        """Inspect container using crictl (for runtime drift detection)"""
        try:
            # Get container info from container runtime
            cmd = ['crictl', 'inspect', container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            self.logger.warning(f"Could not inspect container runtime: {e}")
            return {}
    
    def get_running_containers(self) -> List[str]:
        """Get list of running container IDs on this node"""
        try:
            cmd = ['crictl', 'ps', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip().split('\n')
        except Exception as e:
            self.logger.warning(f"Could not get running containers: {e}")
            return []