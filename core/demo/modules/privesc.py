from core.demo.base import Demo
import time

class PrivescDemo(Demo):
    NAME = "Demo Privilege Escalation"
    DESCRIPTION = "A simulated privilege escalation module that demonstrates common techniques"
    PATH = "post/linux/local/privesc_suid"
    
    OPTIONS = {
        'technique': {
            'description': 'Privilege escalation technique to use',
            'type': str,
            'required': False,
            'default': 'suid',
            'choices': ['suid', 'sudo', 'kernel']
        },
        'session_id': {
            'description': 'ID of the session to escalate privileges in',
            'type': str,
            'required': True
        }
    }
    
    def __init__(self):
        super().__init__()
        self.session_manager = None  # Will be set by DemoManager
    
    def set_session_manager(self, session_manager):
        """Set the session manager to use"""
        self.session_manager = session_manager
    
    def run(self, options: dict) -> dict:
        """Run the privilege escalation"""
        # Update instance options with provided options
        self.options.update(options)
        
        if not self.validate_options():
            return {'error': 'Required options not set'}
        
        if not self.session_manager:
            return {'error': 'Session manager not set'}
        
        session_id = self.options.get('session_id')
        technique = self.options.get('technique', 'suid')
        
        # Get session from session manager
        session = self.session_manager.get_session(session_id)
        
        if not session:
            return {'error': f'Session {session_id} not found'}
        
        if session.info['is_root']:
            return {'error': 'Session already has root privileges'}
        
        # Simulate privilege escalation attempt
        print(f"\n[*] Starting privilege escalation in session {session_id}...")
        time.sleep(1)
        
        if technique == 'suid':
            print("[*] Searching for SUID binaries...")
            time.sleep(0.5)
            print("[+] Found vulnerable SUID binary: /usr/bin/demo-vuln")
            time.sleep(0.5)
            print("[*] Exploiting SUID binary...")
            time.sleep(1)
            print("[+] Exploitation successful!")
            
        elif technique == 'sudo':
            print("[*] Checking sudo permissions...")
            time.sleep(0.5)
            print("[+] Found sudo rule: (ALL : ALL) NOPASSWD: /usr/bin/demo-helper")
            time.sleep(0.5)
            print("[*] Exploiting sudo permissions...")
            time.sleep(1)
            print("[+] Exploitation successful!")
            
        elif technique == 'kernel':
            print("[*] Checking kernel version...")
            time.sleep(0.5)
            print("[+] Found vulnerable kernel version")
            time.sleep(0.5)
            print("[*] Compiling exploit...")
            time.sleep(1)
            print("[*] Running exploit...")
            time.sleep(1)
            print("[+] Kernel exploitation successful!")
        
        # Escalate privileges in the session
        session.escalate_privileges()
        
        print("\n[+] Root shell obtained!")
        return {
            'success': True,
            'technique': technique,
            'session_id': session_id,
            'new_privileges': 'root'
        } 