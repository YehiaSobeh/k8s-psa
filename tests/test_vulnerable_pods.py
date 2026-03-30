import unittest
import yaml
import tempfile
import os
from src.policy_engine import PolicyEngine

class TestVulnerablePods(unittest.TestCase):
    
    def setUp(self):
        # Create a temporary policy file
        self.policy_content = """
checks:
  - id: "privileged_container"
    description: "Container should not run in privileged mode"
    severity: "high"
  - id: "root_container"
    description: "Container should not run as root user"
    severity: "high"
  - id: "host_network"
    description: "Pod should not use host network"
    severity: "medium"
"""
        
        self.temp_policy = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        self.temp_policy.write(self.policy_content)
        self.temp_policy.close()
        
        self.policy_engine = PolicyEngine(self.temp_policy.name)
    
    def tearDown(self):
        os.unlink(self.temp_policy.name)
    
    def test_vulnerable_privileged_pod(self):
        """Test detection of privileged container"""
        vulnerable_pod = {
            'metadata': {
                'name': 'bad-pod',
                'namespace': 'default'
            },
            'spec': {
                'containers': [{
                    'name': 'bad-container',
                    'securityContext': {
                        'privileged': True
                    }
                }]
            }
        }
        
        violations = self.policy_engine.check_pod(vulnerable_pod)
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]['check_id'], 'privileged_container')
        self.assertEqual(violations[0]['severity'], 'high')
    
    def test_vulnerable_root_pod(self):
        """Test detection of container running as root"""
        vulnerable_pod = {
            'metadata': {
                'name': 'root-pod',
                'namespace': 'default'
            },
            'spec': {
                'containers': [{
                    'name': 'root-container',
                    'securityContext': {
                        'runAsUser': 0
                    }
                }]
            }
        }
        
        violations = self.policy_engine.check_pod(vulnerable_pod)
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]['check_id'], 'root_container')
    
    def test_vulnerable_host_network_pod(self):
        """Test detection of pod using host network"""
        vulnerable_pod = {
            'metadata': {
                'name': 'hostnet-pod',
                'namespace': 'default'
            },
            'spec': {
                'hostNetwork': True,
                'containers': [{
                    'name': 'test-container'
                }]
            }
        }
        
        violations = self.policy_engine.check_pod(vulnerable_pod)
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]['check_id'], 'host_network')
        self.assertEqual(violations[0]['severity'], 'medium')
    
    def test_secure_pod(self):
        """Test that secure pods pass all checks"""
        secure_pod = {
            'metadata': {
                'name': 'good-pod',
                'namespace': 'default'
            },
            'spec': {
                'hostNetwork': False,
                'securityContext': {
                    'runAsNonRoot': True,
                    'seccompProfile': {
                        'type': 'RuntimeDefault'
                    }
                },
                'containers': [{
                    'name': 'good-container',
                    'securityContext': {
                        'runAsNonRoot': True,
                        'runAsUser': 1000,
                        'readOnlyRootFilesystem': True,
                        'capabilities': {
                            'drop': ['ALL']
                        }
                    }
                }]
            }
        }
        
        violations = self.policy_engine.check_pod(secure_pod)
        
        self.assertEqual(len(violations), 0, 
                         f"Secure pod should have no violations, but got: {violations}")
    
    def test_multiple_violations(self):
        """Test detection of multiple violations in one pod"""
        vulnerable_pod = {
            'metadata': {
                'name': 'multi-bad-pod',
                'namespace': 'default'
            },
            'spec': {
                'hostNetwork': True,
                'containers': [{
                    'name': 'bad-container',
                    'securityContext': {
                        'privileged': True,
                        'runAsUser': 0
                    }
                }]
            }
        }
        
        violations = self.policy_engine.check_pod(vulnerable_pod)
        
        # Should detect privileged, root, and host network violations
        violation_ids = [v['check_id'] for v in violations]
        self.assertIn('privileged_container', violation_ids)
        self.assertIn('root_container', violation_ids)
        self.assertIn('host_network', violation_ids)
        self.assertEqual(len(violations), 3)

if __name__ == '__main__':
    unittest.main()