import yaml
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class SecurityCheck:
    id: str
    description: str
    severity: str  # high, medium, low
    check_type: str  # container, pod
    check_function: str  # Name of check function

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
        with open(policy_file, 'r') as f:
            return yaml.safe_load(f)
    
    def check_pod(self, pod_info: Dict) -> List[Dict]:
        """Check pod against all policies"""
        violations = []
        
        for check_config in self.policies.get('checks', []):
            check_id = check_config['id']
            if check_id in self.checks:
                check_func = self.checks[check_id]
                result = check_func(pod_info)
                if not result['passed']:
                    violations.append({
                        'check_id': check_id,
                        'description': check_config['description'],
                        'severity': check_config['severity'],
                        'message': result['message'],
                        'pod': pod_info['metadata']['name'],
                        'namespace': pod_info['metadata']['namespace']
                    })
        
        return violations
    
    def _check_privileged(self, pod_info: Dict) -> Dict:
        """Check if container is privileged"""
        for container in pod_info.get('spec', {}).get('containers', []):
            security_context = container.get('securityContext', {})
            if security_context.get('privileged') == True:
                return {
                    'passed': False,
                    'message': f"Container {container['name']} is running in privileged mode"
                }
        return {'passed': True, 'message': ''}
    
    def _check_root_user(self, pod_info: Dict) -> Dict:
        """Check if container runs as root"""
        pod_context = pod_info.get('spec', {}).get('securityContext', {})
        
        for container in pod_info.get('spec', {}).get('containers', []):
            container_context = container.get('securityContext', {})
            
            # Check runAsNonRoot
            run_as_non_root = container_context.get('runAsNonRoot')
            if run_as_non_root is False:
                return {
                    'passed': False,
                    'message': f"Container {container['name']} explicitly allows running as root"
                }
            
            # Check runAsUser
            run_as_user = container_context.get('runAsUser')
            if run_as_user == 0:
                return {
                    'passed': False,
                    'message': f"Container {container['name']} runs as UID 0 (root)"
                }
            
            # Check pod-level security context
            pod_run_as_user = pod_context.get('runAsUser')
            if pod_run_as_user == 0 and run_as_user is None:
                return {
                    'passed': False,
                    'message': f"Container {container['name']} inherits root UID from pod"
                }
        
        return {'passed': True, 'message': ''}
    
    def _check_host_network(self, pod_info: Dict) -> Dict:
        """Check if pod uses host network"""
        if pod_info.get('spec', {}).get('hostNetwork') == True:
            return {
                'passed': False,
                'message': "Pod uses host network namespace"
            }
        return {'passed': True, 'message': ''}
    
    def _check_seccomp(self, pod_info: Dict) -> Dict:
        """Check seccomp profile"""
        pod_context = pod_info.get('spec', {}).get('securityContext', {})
        seccomp_profile = pod_context.get('seccompProfile', {}).get('type', '')
        
        if seccomp_profile not in ['RuntimeDefault', 'Localhost']:
            return {
                'passed': False,
                'message': f"No seccomp profile or unsafe profile: {seccomp_profile}"
            }
        return {'passed': True, 'message': ''}
    
    def _check_capabilities(self, pod_info: Dict) -> Dict:
        """Check for dangerous capabilities"""
        dangerous_caps = ['NET_RAW', 'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE']
        
        for container in pod_info.get('spec', {}).get('containers', []):
            context = container.get('securityContext', {})
            caps = context.get('capabilities', {})
            
            for cap in caps.get('add', []):
                if cap in dangerous_caps:
                    return {
                        'passed': False,
                        'message': f"Container {container['name']} has dangerous capability: {cap}"
                    }
        
        return {'passed': True, 'message': ''}
    
    def _check_readonly_root(self, pod_info: Dict) -> Dict:
        """Check if root filesystem is read-only"""
        for container in pod_info.get('spec', {}).get('containers', []):
            context = container.get('securityContext', {})
            if context.get('readOnlyRootFilesystem') != True:
                return {
                    'passed': False,
                    'message': f"Container {container['name']} root filesystem is not read-only"
                }
        return {'passed': True, 'message': ''}
    
    def _check_host_pid(self, pod_info: Dict) -> Dict:
        """Check if pod uses host PID namespace"""
        if pod_info.get('spec', {}).get('hostPID') == True:
            return {
                'passed': False,
                'message': "Pod uses host PID namespace"
            }
        return {'passed': True, 'message': ''}
    
    def _check_host_ipc(self, pod_info: Dict) -> Dict:
        """Check if pod uses host IPC namespace"""
        if pod_info.get('spec', {}).get('hostIPC') == True:
            return {
                'passed': False,
                'message': "Pod uses host IPC namespace"
            }
        return {'passed': True, 'message': ''}