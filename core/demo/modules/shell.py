from core.demo.base import Demo
from core.output_handler import print_info, print_success, print_error, print_status, print_empty
import time
from typing import Dict, Any

class ShellDemo(Demo):
    NAME = "Demo Shell"
    DESCRIPTION = "A simulated shell with realistic behavior and privilege escalation capabilities"
    PATH = "exploits/cve_shell"
    
    OPTIONS = {
        'host': {
            'description': 'Target host',
            'type': str,
            'required': True,
            'default': '127.0.0.1'
        },
        'port': {   
            'description': 'Target port',
            'type': int,
            'required': True,
            'default': 22
        },
        'type': {
            'description': 'Type of shell to simulate',
            'type': str,
            'required': False,
            'default': 'bash',
            'choices': ['bash', 'cmd', 'powershell']
        },
        'username': {
            'description': 'Initial username',
            'type': str,
            'required': False,
            'default': 'user'
        },
        'is_root': {
            'description': 'Start with root/admin privileges',
            'type': bool,
            'required': False,
            'default': False
        },
        'delay': {
            'description': 'Simulated response delay (in seconds)',
            'type': float,
            'required': False,
            'default': 0.1
        },
        'background': {
            'description': 'Run shell in background (non-interactive)',
            'type': bool,
            'required': False,
            'default': False
        }
    }
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.session_manager = None  # Will be set by DemoManager
    
    def set_session_manager(self, session_manager):
        """Set the session manager to use"""
        self.session_manager = session_manager
    
    def run(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run the demo shell module"""
        if not self.session_manager:
            return {
                'status': 'error',
                'message': 'Session manager not set'
            }
        
        # Simuler les étapes de l'exploit
        print_empty()
        print_status("Starting exploit...")
        time.sleep(0.5)
        
        print_status("Scanning target...")
        time.sleep(1)
        
        print_status("Identifying vulnerable service...")
        time.sleep(0.8)
        
        print_status("Preparing payload...")
        time.sleep(1.2)
        
        print_status("Sending exploit...")
        time.sleep(1.5)
        
        print_status("Checking for successful exploitation...")
        time.sleep(0.7)
        
        # Créer la session
        session = self.session_manager.create_session(
            session_type=options.get('type', 'bash'),
            host='target',
            port=22
        )
        
        # Configurer la session
        session.info.update({
            'user': options.get('username', 'user'),
            'is_root': options.get('is_root', False)
        })
        
        print_success("Exploit completed successfully!")
        time.sleep(0.3)
        
        # Vérifier si on doit exécuter en arrière-plan
        if options.get('background', False):
            print_status(f"Session {session.id} created in background")
            return {
                'status': 'success',
                'message': f'Created background session {session.id}',
                'session_id': session.id
            }
        
        # Mode interactif
        print_empty()
        print_info("Demo Shell - Type 'exit' to quit, 'background' to background the session")
        print_info("Available commands: ls, cd, pwd, cat, whoami, id, echo, env, ps, uname")
        print_info("Network commands: ifconfig, netstat")
        print_info("Bash-specific: sudo, su, history")
        
        # Démarrer la session interactive
        self.session_manager.current_session = session.id
        
        # Retourner le résultat avant de démarrer la session interactive
        result = {
            'status': 'success',
            'message': f'Created session {session.id}',
            'session_id': session.id
        }
        
        # Démarrer la session interactive
        while True:
            try:
                prompt = session.get_prompt()
                command = input(prompt)
                
                if not command:
                    continue
                
                # Commandes de gestion de session
                if command.lower() == 'exit':
                    self.session_manager.kill_session(session.id)
                    self.session_manager.current_session = None
                    print_success("Exited session")
                    break
                elif command.lower() == 'background':
                    self.session_manager.current_session = None
                    print_success(f"Backgrounded session {session.id}")
                    break
                elif command.lower() == 'sessions':
                    self._list_sessions()
                    continue
                elif command.lower().startswith('sessions -i '):
                    new_session_id = command.split()[2]
                    if self.session_manager.interact_session(new_session_id):
                        print_success(f"Interacting with session {new_session_id}")
                        session = self.session_manager.get_session(new_session_id)
                    else:
                        print_error(f"Session {new_session_id} not found")
                    continue
                elif command.lower().startswith('sessions -k '):
                    kill_session_id = command.split()[2]
                    if self.session_manager.kill_session(kill_session_id):
                        print_success(f"Killed session {kill_session_id}")
                        if kill_session_id == session.id:
                            break
                    else:
                        print_error(f"Session {kill_session_id} not found")
                    continue
                
                # Exécuter la commande dans la session
                cmd_result = session.execute(command)
                if cmd_result['output']:
                    print(cmd_result['output'])
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit or 'background' to background session")
            except Exception as e:
                print_error(f"Error: {str(e)}")
        
        return result
    
    def _list_sessions(self):
        """Display active sessions"""
        sessions = self.session_manager.list_sessions()
        
        if not sessions:
            print("\nNo active sessions")
            return
        
        print_empty()
        print_info("Active sessions:")
        print_info("=" * 80)
        print_info(f"{'ID':<10} {'Type':<12} {'User':<10} {'Root':<6} {'Hostname':<15} {'Created':<20}")
        print_info("-" * 80)
        
        current_time = time.time()
        for session in sessions:
            created = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['created_at']))
            is_current = "*" if session['id'] == self.session_manager.current_session else " "
            print_info(f"{is_current}{session['id']:<9} {session['type']:<12} {session['user']:<10} "
                  f"{'yes' if session['is_root'] else 'no':<6} {session['hostname']:<15} {created:<20}")
        print_empty() 