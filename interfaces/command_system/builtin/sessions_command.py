#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sessions command implementation
"""

import time
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class SessionsCommand(BaseCommand):
    """Command to manage sessions"""
    
    @property
    def name(self) -> str:
        return "sessions"
    
    @property
    def description(self) -> str:
        return "Manage active sessions (list, access, kill)"
    
    @property
    def usage(self) -> str:
        return "sessions [list|access|interact|kill|help] [session_id]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage active sessions in the framework.

Subcommands:
    list                    List all active sessions (default)
    access <session_id>     Access/view information about a specific session
    interact <session_id>   Create shell and interact with a session
    kill <session_id>       Terminate a specific session
    kill all                Terminate all sessions
    help                    Show this help message

Examples:
    sessions                # List all sessions
    sessions list           # List all sessions
    sessions access abc123  # View session information
    sessions interact abc123 # Create shell and interact with session
    sessions kill abc123    # Kill session with ID abc123
    sessions kill all       # Kill all sessions
    sessions help           # Show this help message

Session Types:
    - Standard sessions: Regular exploit sessions
    - Browser sessions: Browser-based sessions for web exploitation
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the sessions command"""
        if not args:
            # Default to list if no arguments
            return self._list_sessions()
        
        subcommand = args[0].lower()
        
        try:
            if subcommand == "list":
                return self._list_sessions()
            elif subcommand == "access":
                if len(args) < 2:
                    print_error("Session ID required for access command")
                    print_info("Usage: sessions access <session_id>")
                    return False
                return self._access_session(args[1])
            elif subcommand == "interact":
                if len(args) < 2:
                    print_error("Session ID required for interact command")
                    print_info("Usage: sessions interact <session_id>")
                    return False
                return self._interact_session(args[1])
            elif subcommand == "kill":
                if len(args) < 2:
                    print_error("Session ID required for kill command")
                    print_info("Usage: sessions kill <session_id>")
                    return False
                return self._kill_session(args[1])
            elif subcommand == "help":
                return self._show_help()
            else:
                print_error(f"Unknown subcommand: {subcommand}")
                print_info("Available subcommands: list, access, interact, kill, help")
                return False
                
        except Exception as e:
            print_error(f"Error executing sessions command: {str(e)}")
            return False
    
    def _list_sessions(self) -> bool:
        """List all active sessions"""
        try:
            # Get session manager from framework
            if not hasattr(self.framework, 'session_manager'):
                print_error("Session manager not available")
                return False
            
            session_manager = self.framework.session_manager
            all_sessions = session_manager.get_all_sessions()
            
            standard_sessions = all_sessions.get('standard', [])
            browser_sessions = all_sessions.get('browser', [])
            
            if not standard_sessions and not browser_sessions:
                print_info("No active sessions found")
                return True
            
            print_info("Active Sessions:")
            print_info("=" * 80)
            
            # Display standard sessions
            if standard_sessions:
                print_info(f"\n[STANDARD SESSIONS] ({len(standard_sessions)} sessions)")
                print_info("-" * 80)
                print_info(f"{'ID':<36} {'Host':<20} {'Port':<8} {'Type':<15} {'Status'}")
                print_info("-" * 80)
                
                for session in standard_sessions:
                    status = "Active"
                    print_info(f"{session.id:<36} {session.host:<20} {session.port:<8} {session.session_type:<15} {status}")
            
            # Display browser sessions
            if browser_sessions:
                print_info(f"\n[BROWSER SESSIONS] ({len(browser_sessions)} sessions)")
                print_info("-" * 80)
                print_info(f"{'ID':<36} {'Type':<15} {'Commands':<10} {'Last Seen':<20} {'Status'}")
                print_info("-" * 80)
                
                for session in browser_sessions:
                    status = "Active" if session.get('active', True) else "Inactive"
                    commands_info = f"{session.get('commands_executed', 0)}/{session.get('commands_sent', 0)}"
                    last_seen = self._format_timestamp(session.get('last_seen', 0))
                    print_info(f"{session['id']:<36} {'browser':<15} {commands_info:<10} {last_seen:<20} {status}")
            
            print_info(f"\nTotal: {len(standard_sessions) + len(browser_sessions)} sessions")
            print_info("Use 'sessions access <id>' to interact with a session")
            print_info("Use 'sessions kill <id>' to terminate a session")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing sessions: {str(e)}")
            return False
    
    def _access_session(self, session_id: str) -> bool:
        """Access a specific session"""
        try:
            if not hasattr(self.framework, 'session_manager'):
                print_error("Session manager not available")
                return False
            
            session_manager = self.framework.session_manager
            
            # Check if it's a standard session
            standard_session = session_manager.get_session(session_id)
            if standard_session:
                print_success(f"Accessing standard session: {session_id}")
                print_info(f"Host: {standard_session.host}")
                print_info(f"Port: {standard_session.port}")
                print_info(f"Type: {standard_session.session_type}")
                print_info("Session data:")
                for key, value in standard_session.data.items():
                    print_info(f"  {key}: {value}")
                return True
            
            # Check if it's a browser session
            browser_session = session_manager.get_browser_session(session_id)
            if browser_session:
                print_success(f"Accessing browser session: {session_id}")
                print_info(f"Type: browser")
                print_info(f"Commands executed: {browser_session.get('commands_executed', 0)}")
                print_info(f"Commands sent: {browser_session.get('commands_sent', 0)}")
                print_info(f"First seen: {self._format_timestamp(browser_session.get('first_seen', 0))}")
                print_info(f"Last seen: {self._format_timestamp(browser_session.get('last_seen', 0))}")
                print_info("Session info:")
                for key, value in browser_session.get('info', {}).items():
                    print_info(f"  {key}: {value}")
                return True
            
            print_error(f"Session not found: {session_id}")
            print_info("Use 'sessions list' to see available sessions")
            return False
            
        except Exception as e:
            print_error(f"Error accessing session: {str(e)}")
            return False
    
    def _interact_session(self, session_id: str) -> bool:
        """Interact with a session by creating and switching to appropriate shell"""
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
            
            # Determine session type and appropriate shell type
            if browser_session:
                session_type = "browser"
                shell_type = "javascript"
                # Check if browser server is available for JavaScript shell
                if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
                    print_error("Browser server not available. Cannot create JavaScript shell for browser session.")
                    print_info("Start the browser server first with: browser_server start")
                    return False
            elif session and session.session_type and session.session_type.lower() == "ssh":
                session_type = "ssh"
                shell_type = "ssh"
            elif session and session.session_type and session.session_type.lower() == "android":
                session_type = "android"
                shell_type = "android"
            elif session and session.session_type and session.session_type.lower() in ("php", "http", "https"):
                session_type = session.session_type.lower()
                shell_type = "php"
            elif session and session.session_type and session.session_type.lower() == "mysql":
                session_type = "mysql"
                shell_type = "mysql"
            elif session and session.session_type and session.session_type.lower() == "postgresql":
                session_type = "postgresql"
                shell_type = "postgresql"
            elif session and session.session_type and session.session_type.lower() == "redis":
                session_type = "redis"
                shell_type = "redis"
            elif session and session.session_type and session.session_type.lower() == "ldap":
                session_type = "ldap"
                shell_type = "ldap"
            elif session and session.session_type and session.session_type.lower() == "mongodb":
                session_type = "mongodb"
                shell_type = "mongodb"
            elif session and session.session_type and session.session_type.lower() == "elasticsearch":
                session_type = "elasticsearch"
                shell_type = "elasticsearch"
            elif session and session.session_type and session.session_type.lower() == "mssql":
                session_type = "mssql"
                shell_type = "mssql"
            elif session and session.session_type and session.session_type.lower() == "ftp":
                session_type = "ftp"
                shell_type = "ftp"
            elif session and session.session_type and session.session_type.lower() == "aws":
                session_type = "aws"
                # Check if it's a command executor or interactive shell
                session_data = session.data if hasattr(session, 'data') else {}
                if session_data and session_data.get('command_executor'):
                    shell_type = "aws_sqs_command"
                else:
                    shell_type = "aws_sqs"
            elif session and session.session_type and session.session_type.lower() == "email":
                session_type = "email"
                shell_type = "email"
            else:
                session_type = "standard"
                shell_type = "classic"
            
            # Check if shell already exists
            existing_shell = self.framework.shell_manager.get_shell(session_id)
            if existing_shell:
                print_info(f"Shell already exists for session {session_id}")
                # Switch to existing shell
                success = self.framework.shell_manager.switch_shell(session_id)
                if success:
                    print_success(f"Switched to existing {shell_type} shell for session {session_id}")
                    # Start interactive session
                    return self._start_interactive_session(session_id)
                else:
                    print_error(f"Failed to switch to existing shell for session {session_id}")
                    return False
            
            # Get browser server if available
            browser_server = None
            if hasattr(self.framework, 'browser_server') and self.framework.browser_server:
                browser_server = self.framework.browser_server
            
            # Create new shell
            shell = self.framework.shell_manager.create_shell(
                session_id=session_id,
                shell_type=shell_type,
                session_type=session_type,
                browser_server=browser_server,
                framework=self.framework
            )
            
            if not shell:
                print_error(f"Failed to create {shell_type} shell for session {session_id}")
                return False
            
            # Switch to the new shell
            success = self.framework.shell_manager.switch_shell(session_id)
            if success:
                print_success(f"Created and switched to {shell_type} shell for session {session_id}")
                print_info(f"Shell prompt: {shell.get_prompt()}")
                print_info("You can now execute commands in this shell")
                
                # Start interactive session
                return self._start_interactive_session(session_id)
            else:
                print_error(f"Failed to switch to shell for session {session_id}")
                return False
                
        except Exception as e:
            print_error(f"Error interacting with session: {str(e)}")
            return False
    
    def _start_interactive_session(self, session_id: str) -> bool:
        """Start an interactive session with the shell"""
        try:
            shell = self.framework.shell_manager.get_shell(session_id)
            if not shell:
                print_error(f"No shell found for session {session_id}")
                return False
            
            print_info("Starting interactive session...")
            print_info("Type 'exit', 'back' or 'background' to return to main shell (session remains active), 'help' for shell commands")
            print_info("-" * 50)
            
            while True:
                try:
                    # Check if shell connection is still active (for SSH shells)
                    if hasattr(shell, 'is_connected') and not shell.is_connected:
                        print_error("SSH connection lost. Exiting interactive session...")
                        break
                    
                    # Get shell prompt
                    prompt = shell.get_prompt()
                    command = input(prompt)
                    
                    if not command.strip():
                        continue
                    
                    # Handle special commands
                    if command.lower() in ['exit', 'back', 'background']:
                        print_info("Returning to main shell (session remains active)...")
                        break
                    elif command.lower() == 'help':
                        # Use shell's built-in help command if available
                        result = shell.execute_command('help')
                        if result.get('output'):
                            print_info(result['output'])
                        elif result.get('error'):
                            print_error(result['error'])
                        else:
                            # Fallback to simple help
                            self._show_shell_help(shell)
                        continue
                    
                    # Execute command in shell
                    result = shell.execute_command(command)
                    
                    # Check if result indicates interactive shell should start (check BEFORE displaying output)
                    if result and isinstance(result, dict) and result.get('interactive_shell'):
                        if hasattr(shell, 'start_interactive_shell_loop'):
                            # Don't display the output message, just start the loop directly
                            shell.start_interactive_shell_loop()
                            continue
                        else:
                            print_warning("[DEBUG] Shell does not have start_interactive_shell_loop method")
                    elif result and isinstance(result, dict):
                        # Debug: check if result is a dict but doesn't have interactive_shell flag
                        if command.lower() == 'shell' and 'interactive_shell' not in result:
                            print_warning(f"[DEBUG] Shell command returned result without interactive_shell flag: {list(result.keys())}")
                    
                    # Display output (only if not starting interactive shell)
                    if result and result.get('output'):
                        output = result['output']
                        # Ensure output ends with newline if it doesn't already
                        if output and not output.endswith('\n'):
                            output += '\n'
                        print_info(output)
                    
                    if result and result.get('error'):
                        error_msg = result['error']
                        print_error(error_msg)
                        
                        # Check if error indicates connection lost (SSH, socket, etc.)
                        connection_lost_indicators = [
                            '10054',  # Windows: connection reset by peer
                            '10053',  # Windows: connection aborted
                            'Socket exception',
                            'connexion existante a dû être fermée',
                            'connection closed',
                            'Connection closed',
                            'Connection reset',
                            'connection reset',
                            'SSH execution error',
                            'Socket connection is closed',
                            'Connection closed by remote',
                            'Connection closed by remote host',
                            'Not connected to SSH server'
                        ]
                        
                        # Check if error contains any connection lost indicator
                        error_lower = error_msg.lower()
                        if any(indicator.lower() in error_lower for indicator in connection_lost_indicators):
                            print_error("Connection lost. Exiting interactive session...")
                            # Mark shell as inactive if possible
                            if hasattr(shell, 'disconnect'):
                                try:
                                    shell.disconnect()
                                except:
                                    pass
                            if hasattr(shell, 'deactivate'):
                                try:
                                    shell.deactivate()
                                except:
                                    pass
                            break
                    
                    # Check if shell is still active
                    if not shell.is_active:
                        print_error("Shell has been deactivated")
                        break
                        
                except KeyboardInterrupt:
                    print_info("\nUse 'exit', 'back' or 'background' to return to main shell (session remains active)")
                    continue
                except EOFError:
                    print_info("\nReturning to main shell (session remains active)...")
                    break
                except Exception as e:
                    print_error(f"Error executing command: {str(e)}")
                    continue
            
            return True
            
        except Exception as e:
            print_error(f"Error starting interactive session: {str(e)}")
            return False
    
    def _show_shell_help(self, shell):
        """Show help for the specific shell"""
        try:
            if hasattr(shell, 'get_available_commands'):
                commands = shell.get_available_commands()
                print_info(f"Available commands for {shell.shell_name} shell:")
                print_info("-" * 40)
                for cmd in sorted(commands):
                    print_info(f"  {cmd}")
                print_info("-" * 40)
                print_info("Special commands: exit/back/background (return to main shell, session remains active), help")
            else:
                print_info("No command help available for this shell")
        except Exception as e:
            print_error(f"Error showing shell help: {str(e)}")
    
    def _kill_session(self, session_id: str) -> bool:
        """Kill a specific session or all sessions"""
        try:
            if not hasattr(self.framework, 'session_manager'):
                print_error("Session manager not available")
                return False
            
            session_manager = self.framework.session_manager
            
            if session_id.lower() == "all":
                return self._kill_all_sessions(session_manager)
            
            # Try to kill standard session
            if session_manager.remove_session(session_id):
                print_success(f"Standard session killed: {session_id}")
                return True
            
            # Try to kill browser session
            if session_manager.remove_browser_session(session_id):
                print_success(f"Browser session killed: {session_id}")
                return True
            
            print_error(f"Session not found: {session_id}")
            print_info("Use 'sessions list' to see available sessions")
            return False
            
        except Exception as e:
            print_error(f"Error killing session: {str(e)}")
            return False
    
    def _kill_all_sessions(self, session_manager) -> bool:
        """Kill all sessions"""
        try:
            all_sessions = session_manager.get_all_sessions()
            standard_sessions = all_sessions.get('standard', [])
            browser_sessions = all_sessions.get('browser', [])
            
            total_sessions = len(standard_sessions) + len(browser_sessions)
            
            if total_sessions == 0:
                print_info("No sessions to kill")
                return True
            
            # Confirm before killing all sessions
            print_warning(f"This will kill {total_sessions} sessions:")
            print_info(f"  - {len(standard_sessions)} standard sessions")
            print_info(f"  - {len(browser_sessions)} browser sessions")
            
            # For now, we'll proceed without confirmation
            # In a real implementation, you might want to add confirmation
            
            killed_count = 0
            
            # Kill standard sessions
            for session in standard_sessions[:]:  # Copy list to avoid modification during iteration
                if session_manager.remove_session(session.id):
                    killed_count += 1
                    print_success(f"Killed standard session: {session.id}")
            
            # Kill browser sessions
            for session in browser_sessions[:]:  # Copy list to avoid modification during iteration
                if session_manager.remove_browser_session(session['id']):
                    killed_count += 1
                    print_success(f"Killed browser session: {session['id']}")
            
            print_success(f"Successfully killed {killed_count} sessions")
            return True
            
        except Exception as e:
            print_error(f"Error killing all sessions: {str(e)}")
            return False
    
    def _format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display"""
        try:
            if timestamp == 0:
                return "Never"
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Invalid"
    
    def _show_help(self) -> bool:
        """Show detailed help for the sessions command"""
        try:
            print_info(self.help_text)
            return True
        except Exception as e:
            print_error(f"Error showing help: {str(e)}")
            return False
