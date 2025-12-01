from typing import Dict, Any, Optional, List
from .filesystem import VirtualFileSystem

class BaseShell:
    def __init__(self, username: str = "user", is_root: bool = False):
        self.username = username
        self.is_root = is_root
        self.hostname = "demo-machine"
        self.fs = VirtualFileSystem()
        self.current_dir = f"/home/{username}" if username != "root" else "/root"
        self.env_vars = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': f'/home/{username}' if username != "root" else "/root",
            'USER': username,
            'PWD': self.current_dir,
            'SHELL': '/bin/bash'
        }
        
        # Register basic commands
        self.commands = {
            'ls': self.cmd_ls,
            'cd': self.cmd_cd,
            'pwd': self.cmd_pwd,
            'cat': self.cmd_cat,
            'whoami': self.cmd_whoami,
            'id': self.cmd_id,
            'echo': self.cmd_echo,
            'env': self.cmd_env
        }
    
    def get_prompt(self) -> str:
        """Get the shell prompt"""
        if self.is_root:
            return f"root@{self.hostname}:{self.current_dir}# "
        return f"{self.username}@{self.hostname}:{self.current_dir}$ "
    
    def execute(self, command: str) -> Dict[str, Any]:
        """Execute a command in the shell"""
        if not command.strip():
            return {'output': '', 'status': 0}
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd in self.commands:
            try:
                return self.commands[cmd](args)
            except Exception as e:
                return {'output': f"Error: {str(e)}", 'status': 1}
        
        return {'output': f"Command not found: {cmd}", 'status': 127}
    
    def cmd_ls(self, args: List[str]) -> Dict[str, Any]:
        """List directory contents"""
        path = args[0] if args else self.current_dir
        entries = self.fs.list_dir(path, self.username, self.is_root)
        
        output = []
        for entry in entries:
            if entry['type'] == 'dir':
                name = f"\033[1;34m{entry['name']}/\033[0m"  # Blue for directories
            else:
                if int(entry['permissions']) & 0o100:  # Executable
                    name = f"\033[1;32m{entry['name']}\033[0m"  # Green for executables
                else:
                    name = entry['name']
            perms = entry['permissions']
            owner = entry['owner']
            output.append(f"{perms} {owner:8} {name}")
        
        return {'output': '\n'.join(output), 'status': 0}
    
    def cmd_cd(self, args: List[str]) -> Dict[str, Any]:
        """Change directory"""
        path = args[0] if args else self.env_vars['HOME']
        
        # Normalize path
        if not path.startswith('/'):
            path = f"{self.current_dir}/{path}"
        
        # Check if directory exists
        dir_node = self.fs._get_node_at_path(path)
        if not dir_node:
            return {'output': f"cd: {path}: No such file or directory", 'status': 1}
        
        self.current_dir = self.fs._normalize_path(path)
        self.env_vars['PWD'] = self.current_dir
        return {'output': '', 'status': 0}
    
    def cmd_pwd(self, args: List[str]) -> Dict[str, Any]:
        """Print working directory"""
        return {'output': self.current_dir, 'status': 0}
    
    def cmd_cat(self, args: List[str]) -> Dict[str, Any]:
        """Display file contents"""
        if not args:
            return {'output': "cat: missing operand", 'status': 1}
        
        path = args[0]
        content = self.fs.read_file(path, self.username, self.is_root)
        
        if content is None:
            return {'output': f"cat: {path}: No such file or permission denied", 'status': 1}
        
        return {'output': content, 'status': 0}
    
    def cmd_whoami(self, args: List[str]) -> Dict[str, Any]:
        """Print current user"""
        return {'output': self.username, 'status': 0}
    
    def cmd_id(self, args: List[str]) -> Dict[str, Any]:
        """Print user and group IDs"""
        if self.is_root:
            output = "uid=0(root) gid=0(root) groups=0(root)"
        else:
            output = f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})"
        return {'output': output, 'status': 0}
    
    def cmd_echo(self, args: List[str]) -> Dict[str, Any]:
        """Echo arguments"""
        return {'output': ' '.join(args), 'status': 0}
    
    def cmd_env(self, args: List[str]) -> Dict[str, Any]:
        """Print environment variables"""
        output = []
        for key, value in self.env_vars.items():
            output.append(f"{key}={value}")
        return {'output': '\n'.join(output), 'status': 0}
    
    def escalate_privileges(self) -> bool:
        """Escalate to root privileges"""
        self.is_root = True
        self.username = "root"
        self.env_vars['USER'] = 'root'
        self.env_vars['HOME'] = '/root'
        if self.current_dir.startswith('/home/'):
            self.current_dir = '/root'
        return True 