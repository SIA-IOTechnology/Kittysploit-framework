from typing import Dict, Any, Optional, List
from .shell.shells import BashShell, PowerShellShell, CmdShell
import random
import string
import time

class DemoSession:
    def __init__(self, shell_type: str = "bash", username: str = "user", is_root: bool = False):
        self.id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.shell_type = shell_type
        self.shell = self._create_shell(shell_type, username, is_root)
        self.created_at = time.time()
        self.last_seen = time.time()
        self.info = {
            'type': shell_type,
            'user': username,
            'is_root': is_root,
            'hostname': self.shell.hostname
        }
    
    def _create_shell(self, shell_type: str, username: str, is_root: bool):
        """Create appropriate shell instance"""
        if shell_type == "bash":
            return BashShell(username, is_root)
        elif shell_type == "powershell":
            return PowerShellShell(username, is_root)
        elif shell_type == "cmd":
            return CmdShell(username, is_root)
        else:
            raise ValueError(f"Unknown shell type: {shell_type}")
    
    def execute(self, command: str) -> Dict[str, Any]:
        """Execute a command in the session's shell"""
        self.last_seen = time.time()
        return self.shell.execute(command)
    
    def get_prompt(self) -> str:
        """Get the shell prompt"""
        return self.shell.get_prompt()
    
    def escalate_privileges(self) -> bool:
        """Escalate privileges in the session"""
        result = self.shell.escalate_privileges()
        if result:
            self.info['is_root'] = True
            self.info['user'] = 'root'
        return result

class DemoSessionManager:
    def __init__(self):
        self.sessions: Dict[str, DemoSession] = {}
        self.current_session: Optional[str] = None
    
    def create_session(self, shell_type: str = "bash", username: str = "user", is_root: bool = False) -> DemoSession:
        """Create a new session"""
        session = DemoSession(shell_type, username, is_root)
        self.sessions[session.id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[DemoSession]:
        """Get a session by ID"""
        return self.sessions.get(session_id)
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions"""
        sessions = []
        for session_id, session in self.sessions.items():
            sessions.append({
                'id': session_id,
                'type': session.shell_type,
                'user': session.info['user'],
                'is_root': session.info['is_root'],
                'hostname': session.info['hostname'],
                'created_at': session.created_at,
                'last_seen': session.last_seen
            })
        return sessions
    
    def kill_session(self, session_id: str) -> bool:
        """Kill a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            if self.current_session == session_id:
                self.current_session = None
            return True
        return False
    
    def interact_session(self, session_id: str) -> Optional[DemoSession]:
        """Set the current interactive session"""
        if session_id in self.sessions:
            self.current_session = session_id
            return self.sessions[session_id]
        return None
    
    def get_current_session(self) -> Optional[DemoSession]:
        """Get the current interactive session"""
        if self.current_session:
            return self.sessions.get(self.current_session)
        return None
    
    def execute_in_session(self, session_id: str, command: str) -> Dict[str, Any]:
        """Execute a command in a specific session"""
        session = self.get_session(session_id)
        if not session:
            return {'error': f'Session {session_id} not found', 'status': 1}
        return session.execute(command)
    
    def cleanup_old_sessions(self, max_age: int = 3600) -> int:
        """Remove sessions older than max_age seconds"""
        current_time = time.time()
        old_sessions = [
            sid for sid, session in self.sessions.items()
            if current_time - session.last_seen > max_age
        ]
        
        for sid in old_sessions:
            self.kill_session(sid)
        
        return len(old_sessions) 