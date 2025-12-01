from typing import Dict, Any, List
from .base import BaseShell

class BashShell(BaseShell):
    def __init__(self, username: str = "user", is_root: bool = False):
        super().__init__(username, is_root)
        self.env_vars['SHELL'] = '/bin/bash'
        
        # Add bash-specific commands
        self.commands.update({
            'sudo': self.cmd_sudo,
            'su': self.cmd_su,
            'bash': self.cmd_bash,
            'history': self.cmd_history
        })
    
    def cmd_sudo(self, args: List[str]) -> Dict[str, Any]:
        """Simulate sudo command"""
        if self.is_root:
            return {'output': "You are already root!", 'status': 1}
        
        if not args:
            return {'output': "sudo: command required", 'status': 1}
        
        # Simulate privilege escalation
        old_username = self.username
        old_is_root = self.is_root
        self.escalate_privileges()
        
        # Execute command with root privileges
        result = self.execute(' '.join(args))
        
        # Restore original privileges
        self.username = old_username
        self.is_root = old_is_root
        return result
    
    def cmd_su(self, args: List[str]) -> Dict[str, Any]:
        """Simulate su command"""
        target_user = args[0] if args else "root"
        
        if target_user == "root" and not self.is_root:
            return {'output': "su: Authentication failure", 'status': 1}
        
        if target_user == "root":
            self.escalate_privileges()
            return {'output': "", 'status': 0}
        
        return {'output': f"su: user {target_user} does not exist", 'status': 1}
    
    def cmd_bash(self, args: List[str]) -> Dict[str, Any]:
        """Start a new bash shell"""
        return {'output': "Already in bash shell", 'status': 0}
    
    def cmd_history(self, args: List[str]) -> Dict[str, Any]:
        """Show command history"""
        history_file = f"{self.env_vars['HOME']}/.bash_history"
        result = self.cmd_cat([history_file])
        if result['status'] == 0:
            return result
        return {'output': "No history available", 'status': 0}

class PowerShellShell(BaseShell):
    def __init__(self, username: str = "user", is_root: bool = False):
        super().__init__(username, is_root)
        self.env_vars['SHELL'] = 'powershell'
        self.hostname = "DEMO-PC"
        
        # Override some commands with PowerShell equivalents
        self.commands.update({
            'ls': self.cmd_dir,
            'pwd': self.cmd_pwd,
            'cat': self.cmd_type,
            'Get-ChildItem': self.cmd_dir,
            'Set-Location': self.cmd_cd,
            'Get-Location': self.cmd_pwd,
            'Get-Content': self.cmd_type
        })
    
    def get_prompt(self) -> str:
        """Get PowerShell-style prompt"""
        if self.is_root:
            return f"PS {self.current_dir} [Administrator]> "
        return f"PS {self.current_dir}> "
    
    def cmd_dir(self, args: List[str]) -> Dict[str, Any]:
        """PowerShell Get-ChildItem"""
        result = super().cmd_ls(args)
        # Convert to PowerShell format
        if result['status'] == 0:
            lines = result['output'].split('\n')
            output = []
            for line in lines:
                if line:
                    parts = line.split()
                    mode = 'd' if '/\033[0m' in parts[-1] else '-'
                    name = parts[-1].replace('\033[1;34m', '').replace('\033[1;32m', '').replace('\033[0m', '')
                    output.append(f"{mode.ljust(4)} {parts[1].ljust(10)} {name}")
            result['output'] = '\n'.join(output)
        return result
    
    def cmd_type(self, args: List[str]) -> Dict[str, Any]:
        """PowerShell Get-Content"""
        return super().cmd_cat(args)

class CmdShell(BaseShell):
    def __init__(self, username: str = "user", is_root: bool = False):
        super().__init__(username, is_root)
        self.env_vars['SHELL'] = 'cmd.exe'
        self.hostname = "DEMO-PC"
        
        # Override commands with CMD equivalents
        self.commands.update({
            'ls': self.cmd_dir,
            'dir': self.cmd_dir,
            'cd': self.cmd_cd,
            'type': self.cmd_type,
            'echo': self.cmd_echo,
            'whoami': self.cmd_whoami,
            'set': self.cmd_set
        })
    
    def get_prompt(self) -> str:
        """Get CMD-style prompt"""
        drive = self.current_dir.split('/')[1] if len(self.current_dir.split('/')) > 1 else 'C'
        path = self.current_dir.replace('/', '\\')
        return f"{drive}:{path}>"
    
    def cmd_dir(self, args: List[str]) -> Dict[str, Any]:
        """CMD dir command"""
        result = super().cmd_ls(args)
        if result['status'] == 0:
            lines = result['output'].split('\n')
            output = [" Directory of " + self.current_dir.replace('/', '\\')]
            for line in lines:
                if line:
                    parts = line.split()
                    is_dir = '/\033[0m' in parts[-1]
                    name = parts[-1].replace('\033[1;34m', '').replace('\033[1;32m', '').replace('\033[0m', '')
                    if is_dir:
                        output.append(f"<DIR>          {name}")
                    else:
                        output.append(f"               {name}")
            result['output'] = '\n'.join(output)
        return result
    
    def cmd_type(self, args: List[str]) -> Dict[str, Any]:
        """CMD type command"""
        return super().cmd_cat(args)
    
    def cmd_set(self, args: List[str]) -> Dict[str, Any]:
        """CMD set command"""
        if not args:
            output = []
            for key, value in self.env_vars.items():
                output.append(f"{key}={value}")
            return {'output': '\n'.join(output), 'status': 0}
        
        if '=' in args[0]:
            key, value = args[0].split('=', 1)
            self.env_vars[key] = value
            return {'output': '', 'status': 0}
        
        return {'output': f"Environment variable {args[0]} not defined", 'status': 1} 