#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shell command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class ShellCommand(BaseCommand):
    """Command to manage shells"""
    
    @property
    def name(self) -> str:
        return "shell"
    
    @property
    def description(self) -> str:
        return "Manage shells for different session types"
    
    @property
    def usage(self) -> str:
        return "shell [create|list|switch|info|help] [options]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage shells for different session types.

Subcommands:
    create <session_id> <shell_type>  Create a shell for a session
    list                              List all shells
    switch <session_id>               Switch to a shell
    info <session_id>                 Show shell information
    help                              Show this help message

Shell Types:
    classic      Standard shell for regular sessions
    javascript   JavaScript shell for browser sessions
    ssh          SSH shell for SSH sessions
    android      Android (ADB) shell for Android sessions
    php          PHP shell for webshell/HTTP sessions
    mysql        MySQL shell for MySQL database sessions
    ftp          FTP shell for FTP file transfer sessions

Examples:
    shell create abc123 classic        # Create classic shell for session abc123
    shell list                         # List all shells
    shell switch abc123                # Switch to shell for session abc123
    shell info abc123                  # Show info for shell abc123
    shell help                         # Show this help message
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the shell command"""
        if not args:
            return self._list_shells()
        
        subcommand = args[0].lower()
        
        try:
            if subcommand == "create":
                if len(args) < 3:
                    print_error("Session ID and shell type required for create command")
                    print_info("Usage: shell create <session_id> <shell_type>")
                    return False
                return self._create_shell(args[1], args[2])
            elif subcommand == "list":
                return self._list_shells()
            elif subcommand == "switch":
                if len(args) < 2:
                    print_error("Session ID required for switch command")
                    print_info("Usage: shell switch <session_id>")
                    return False
                return self._switch_shell(args[1])
            elif subcommand == "info":
                if len(args) < 2:
                    print_error("Session ID required for info command")
                    print_info("Usage: shell info <session_id>")
                    return False
                return self._show_shell_info(args[1])
            elif subcommand == "help":
                return self._show_help()
            else:
                print_error(f"Unknown subcommand: {subcommand}")
                print_info("Available subcommands: create, list, switch, info, help")
                return False
                
        except Exception as e:
            print_error(f"Error executing shell command: {str(e)}")
            return False
    
    def _create_shell(self, session_id: str, shell_type: str) -> bool:
        """Create a shell for a session"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            # Check if session exists
            session = self.framework.session_manager.get_session(session_id)
            browser_session = self.framework.session_manager.get_browser_session(session_id)
            
            if not session and not browser_session:
                print_error(f"Session not found: {session_id}")
                print_info("Use 'sessions list' to see available sessions")
                return False
            
            # Determine session type
            session_type = "browser" if browser_session else "standard"
            
            # Create shell
            shell = self.framework.shell_manager.create_shell(
                session_id=session_id,
                shell_type=shell_type,
                session_type=session_type
            )
            
            if shell:
                print_success(f"Created {shell_type} shell for session {session_id}")
                return True
            else:
                print_error(f"Failed to create {shell_type} shell for session {session_id}")
                return False
                
        except Exception as e:
            print_error(f"Error creating shell: {str(e)}")
            return False
    
    def _list_shells(self) -> bool:
        """List all shells"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            shells = self.framework.shell_manager.list_shells()
            
            if not shells:
                print_info("No shells found")
                return True
            
            print_info("Active Shells:")
            print_info("=" * 80)
            print_info(f"{'Session ID':<36} {'Type':<12} {'Status':<8} {'User':<15} {'Commands'}")
            print_info("-" * 80)
            
            for shell_info in shells:
                status = "Active" if shell_info.get('is_active', False) else "Inactive"
                active_marker = " *" if shell_info.get('is_active', False) else ""
                print_info(f"{shell_info['session_id']:<36} {shell_info['shell_name']:<12} {status:<8} {shell_info['username']:<15} {shell_info['command_count']}{active_marker}")
            
            print_info(f"\nTotal: {len(shells)} shells")
            print_info("Use 'shell switch <session_id>' to switch to a shell")
            print_info("Use 'shell info <session_id>' to get detailed information")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing shells: {str(e)}")
            return False
    
    def _switch_shell(self, session_id: str) -> bool:
        """Switch to a shell"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            success = self.framework.shell_manager.switch_shell(session_id)
            if success:
                print_success(f"Switched to shell for session {session_id}")
                return True
            else:
                print_error(f"Failed to switch to shell for session {session_id}")
                return False
                
        except Exception as e:
            print_error(f"Error switching shell: {str(e)}")
            return False
    
    def _show_shell_info(self, session_id: str) -> bool:
        """Show shell information"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            shell_info = self.framework.shell_manager.get_shell_info(session_id)
            if not shell_info:
                print_error(f"Shell not found for session {session_id}")
                return False
            
            print_info(f"Shell Information for Session {session_id}:")
            print_info("=" * 50)
            print_info(f"Shell Name: {shell_info['shell_name']}")
            print_info(f"Session Type: {shell_info['session_type']}")
            print_info(f"Status: {'Active' if shell_info['is_active'] else 'Inactive'}")
            print_info(f"Username: {shell_info['username']}")
            print_info(f"Hostname: {shell_info['hostname']}")
            print_info(f"Root: {'Yes' if shell_info['is_root'] else 'No'}")
            print_info(f"Current Directory: {shell_info['current_directory']}")
            print_info(f"Commands Executed: {shell_info['command_count']}")
            print_info(f"Available Commands: {shell_info['available_commands']}")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing shell info: {str(e)}")
            return False
    
    def _show_help(self) -> bool:
        """Show detailed help for the shell command"""
        try:
            print_info(self.help_text)
            return True
        except Exception as e:
            print_error(f"Error showing help: {str(e)}")
            return False
