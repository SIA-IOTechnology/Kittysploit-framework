#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Run command implementation
"""

import argparse
import socket
import time
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_empty

class RunCommand(BaseCommand):
    """Command to run the current module"""
    
    @property
    def name(self) -> str:
        return "run"
    
    @property
    def description(self) -> str:
        return "Execute the current module"
    
    @property
    def usage(self) -> str:
        return "run [--preview] [--background]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command executes the currently selected module. Make sure to set
all required options before running.

Options:
    --preview                 Show execution preview without running
    --background              Run module in background (for listeners)

Examples:
    run                       # Execute the current module
    run --preview             # Show execution preview
    run --background          # Run listener in background
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Execute the current module",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.add_argument(
            '--preview',
            action='store_true',
            help='Show execution preview without running'
        )
        
        parser.add_argument(
            '--background',
            action='store_true',
            help='Run module in background (for listeners)'
        )
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the run command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
            print_error("No module selected. Use 'use <module>' first.")
            return False
        
        module = self.framework.current_module
        
        try:
            # Check if all required options are set
            if not module.check_options():
                missing = module.get_missing_options()
                if missing:
                    print_error(f"Missing required options: {', '.join(missing)}")
                else:
                    print_error("Not all required options are set")
                print_info("Use 'show options' to see required options")
                return False
            
            # Vérifier la blacklist du Guardian avant l'exécution
            if hasattr(self.framework, 'guardian_manager') and self.framework.guardian_manager and self.framework.guardian_manager.enabled and self.framework.guardian_manager.verbose:
                print_info(f"[GUARDIAN DEBUG] Checking guardian - has guardian_manager: {hasattr(self.framework, 'guardian_manager')}")
                if hasattr(self.framework, 'guardian_manager'):
                    print_info(f"[GUARDIAN DEBUG] guardian_manager exists: {self.framework.guardian_manager is not None}")
                    if self.framework.guardian_manager:
                        print_info(f"[GUARDIAN DEBUG] guardian_manager.enabled: {self.framework.guardian_manager.enabled}")
                        print_info(f"[GUARDIAN DEBUG] blacklist size: {len(self.framework.guardian_manager.blacklist)}")
                        print_info(f"[GUARDIAN DEBUG] blacklist contents: {list(self.framework.guardian_manager.blacklist.keys())}")
            
            if hasattr(self.framework, 'guardian_manager') and self.framework.guardian_manager and self.framework.guardian_manager.enabled:
                target_ip = self.framework._extract_target_ip_from_module()
                if self.framework.guardian_manager.verbose:
                    print_info(f"[GUARDIAN DEBUG] Extracted target IP: {target_ip}")
                if target_ip:
                    # Vérifier si l'IP est dans la blacklist
                    is_blacklisted = target_ip in self.framework.guardian_manager.blacklist
                    if self.framework.guardian_manager.verbose:
                        print_info(f"[GUARDIAN DEBUG] Is {target_ip} in blacklist? {is_blacklisted}")
                    if is_blacklisted:
                        blacklist_entry = self.framework.guardian_manager.blacklist[target_ip]
                        reason = blacklist_entry.get('reason', 'Unknown reason')
                        timestamp = blacklist_entry.get('timestamp', 'Unknown')
                        
                        print_error(f"[GUARDIAN] Module execution BLOCKED: Target IP {target_ip} is blacklisted")
                        print_error(f"[GUARDIAN] Reason: {reason} (added: {timestamp})")
                        
                        # Créer une alerte Guardian via _create_alert pour mettre à jour les statistiques
                        alert = self.framework.guardian_manager._create_alert(
                            target=target_ip,
                            severity="CRITICAL",
                            issue=f"Module execution blocked: IP {target_ip} is blacklisted",
                            confidence=100.0,
                            recommendations=[
                                "Remove IP from blacklist if this is intentional",
                                "Verify target before removing from blacklist"
                            ],
                            evidence=[f"IP {target_ip} found in blacklist"]
                        )
                        # Marquer l'action comme prise
                        alert.auto_action_taken = True
                        alert.action_description = "Module execution blocked"
                        
                        return False
            
            # Show preview if requested
            if parsed_args.preview:
                self._show_execution_preview(module)
                return True
            
            # Check if module requires root privileges
            if module.requires_root:
                print_warning("This module requires root privileges")
                # In a real implementation, you might want to check actual privileges
            
            # Execute the module
            print_info(f"Executing module: {module.name}")
            print_info("=" * 50)
            
            # Check if it's a listener module
            if hasattr(module, 'type') and module.type == 'listener':
                # Check if run() method accepts background parameter
                import inspect
                run_signature = inspect.signature(module.run)
                accepts_background = 'background' in run_signature.parameters
                
                if parsed_args.background:
                    print_info("Listener module detected. Running in background mode.")
                    try:
                        # For background mode, use direct run() but still create session if result is a tuple
                        if accepts_background:
                            result = module.run(background=True)
                        else:
                            result = module.run()
                        
                        # If result is a tuple with (connection, target, port), create session automatically
                        if isinstance(result, tuple) and len(result) >= 3:
                            connection, target, port = result[0], result[1], result[2]
                            additional_data = result[3] if len(result) > 3 else {}
                            
                            # Create session automatically using listener's _create_session_from_connection_data
                            if hasattr(module, '_create_session_from_connection_data'):
                                session_id = module._create_session_from_connection_data(
                                    connection, target, port, additional_data
                                )
                                if session_id:
                                    print_success(f"Session {session_id} created automatically")
                                    # Convert result to boolean for command history
                                    success = True
                                else:
                                    print_error("Failed to create session automatically")
                                    success = False
                            else:
                                # Fallback: use run_with_auto_session if available
                                if hasattr(module, 'run_with_auto_session'):
                                    session_id = module.run_with_auto_session()
                                    success = bool(session_id) if session_id else False
                                else:
                                    success = False
                        # If result is a session ID (string), it's already created
                        elif isinstance(result, str) and result:
                            print_success(f"Session {result} created")
                            success = True
                        # Convert result to boolean for command history
                        else:
                            success = bool(result) if result is not None else False
                        
                        if success:
                            print_success("Listener started in background")
                            # Register as a background job
                            self._register_background_job(module)
                        else:
                            print_error("Failed to start listener in background")
                        return success
                    except Exception as e:
                        print_error(f"Error starting listener in background: {e}")
                        return False
                else:
                    print_info("Listener module detected. Press Ctrl+C to stop.")
                    try:
                        # Use run_with_auto_session for listeners to automatically create sessions
                        if hasattr(module, 'run_with_auto_session'):
                            result = module.run_with_auto_session()
                            
                            # If result is a session_id (string), automatically start interactive session
                            if isinstance(result, str) and result:
                                session_id = result
                                print_success(f"Session {session_id} created. Starting interactive shell...")
                                
                                # Automatically start interactive session
                                return self._start_interactive_session_for_listener(session_id)
                            
                            # Convert result to boolean for command history
                            success = bool(result) if result is not None else False
                            if success:
                                print_success("Module execution completed successfully")
                            else:
                                print_error("Module execution failed")
                            return success
                        else:
                            # Fallback to direct run() if run_with_auto_session is not available
                            if accepts_background:
                                result = module.run(background=False)
                            else:
                                result = module.run()
                            # Convert result to boolean for command history
                            success = bool(result) if result is not None else False
                            if success:
                                print_success("Module execution completed successfully")
                            else:
                                print_error("Module execution failed")
                            return success
                    except KeyboardInterrupt:
                        print_info("\n[!] Interrupted by user")
                        # Call shutdown method if available
                        if hasattr(module, 'shutdown'):
                            try:
                                module.shutdown()
                                print_info("Listener stopped gracefully")
                            except Exception as e:
                                print_warning(f"Error during shutdown: {e}")
                        return True
            else:
                # Check if it's a payload module
                is_payload = (hasattr(module, 'type') and module.type == 'payload') or \
                            (hasattr(module, 'TYPE_MODULE') and module.TYPE_MODULE == 'payload')
                
                if is_payload:
                    # For payloads, use generate() instead of run()
                    print_info("Payload module detected. Generating payload...")
                    try:
                        payload_result = module.generate()
                        if payload_result:
                            print_success("Payload generated successfully!")
                            print_info(f"Payload: {payload_result}")
                            return True
                        else:
                            print_error("Failed to generate payload")
                            return False
                    except Exception as e:
                        print_error(f"Error generating payload: {e}")
                        return False
                
                # Regular module execution
                if parsed_args.background:
                    print_info("Running module in background mode.")
                    try:
                        # Check if run() method accepts background parameter
                        import inspect
                        try:
                            run_signature = inspect.signature(module.run)
                            accepts_background = 'background' in run_signature.parameters
                        except (ValueError, TypeError):
                            # If signature inspection fails, assume no background parameter
                            accepts_background = False
                        
                        if accepts_background:
                            result = module.run(background=True)
                        else:
                            result = module.run()
                        # Convert result to boolean for command history
                        success = bool(result) if result is not None else False
                        if success:
                            print_success("Module started in background")
                            # Register as a background job
                            self._register_background_job(module)
                        else:
                            print_error("Failed to start module in background")
                        return success
                    except Exception as e:
                        print_error(f"Error starting module in background: {e}")
                        return False
                else:
                    result = module._exploit()
                    
                    # Convert result to boolean for command history
                    success = bool(result) if result is not None else False
                    
                    if success:
                        print_success("Module execution completed successfully")
                    else:
                        print_error("Module execution failed")
                    
                    return success
            
        except Exception as e:
            print_error(f"Error executing module: {str(e)}")
            return False
    
    def _register_background_job(self, module):
        """Register a module as a background job"""
        try:
            from core.job_manager import global_job_manager
            
            # Generate job name based on module type and name
            job_name = f"{module.type} {module.name}"
            if hasattr(module, 'lhost') and hasattr(module, 'lport'):
                # For listeners, include host and port
                host = str(module.lhost.value)
                port = int(module.lport.value)
                job_name = f"{module.type} {module.name} on {host}:{port}"
            
            job_id = global_job_manager.add_job(
                name=job_name,
                description=f"{module.type} module: {module.name}",
                module=module
            )
            
            if job_id:
                print_success(f"Module registered as background job [ID: {job_id}]")
                # Store job_id in module for later reference
                if hasattr(module, 'job_id'):
                    module.job_id = job_id
            else:
                print_warning("Failed to register module as background job")
                
        except Exception as e:
            print_warning(f"Could not register module as background job: {e}")
    
    def _show_execution_preview(self, module):
        """Show execution preview for the module"""
        # Analyze the module dynamically
        print_info("To be implemented ....")
        print_info("Feature incoming ....")


    
    def _start_interactive_session_for_listener(self, session_id: str) -> bool:
        """Start an interactive session for a listener-created session"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            # Check if session exists
            session = self.framework.session_manager.get_session(session_id)
            if not session:
                print_error(f"Session not found: {session_id}")
                return False
            
            # Determine shell type based on session type
            session_type = session.session_type.lower() if session.session_type else "standard"
            if session_type == "ssh":
                shell_type = "ssh"
            elif session_type == "meterpreter":
                shell_type = "meterpreter"
            elif session_type in ("php", "http", "https"):
                shell_type = "php"
            elif session_type == "mysql":
                shell_type = "mysql"
            elif session_type == "postgresql":
                shell_type = "postgresql"
            elif session_type == "redis":
                shell_type = "redis"
            elif session_type == "ldap":
                shell_type = "ldap"
            elif session_type == "mongodb":
                shell_type = "mongodb"
            elif session_type == "elasticsearch":
                shell_type = "elasticsearch"
            elif session_type == "mssql":
                shell_type = "mssql"
            elif session_type == "ftp":
                shell_type = "ftp"
            elif session_type == "aws":
                # Check if it's a command executor or interactive shell
                session_data = session.data if hasattr(session, 'data') else {}
                if session_data and session_data.get('command_executor'):
                    shell_type = "aws_sqs_command"
                else:
                    shell_type = "aws_sqs"
            elif session_type == "android":
                shell_type = "android"
            else:
                shell_type = "classic"
            
            # Create shell if it doesn't exist
            shell = self.framework.shell_manager.get_shell(session_id)
            if not shell:
                shell = self.framework.shell_manager.create_shell(
                    session_id=session_id,
                    shell_type=shell_type,
                    session_type=session_type,
                    framework=self.framework
                )
            
            if not shell:
                print_error(f"Failed to create shell for session {session_id}")
                return False
            
            # Set as active shell
            self.framework.shell_manager.set_active_shell(session_id)
            
            # Start interactive session
            print_info("Starting interactive session...")
            print_info("Type 'exit', 'back' or 'background' to return to main shell (session remains active), 'help' for shell commands")
            print_info("-" * 50)
            
            while True:
                try:
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
                    
                    # Check if result indicates interactive shell should start
                    if result and isinstance(result, dict) and result.get('interactive_shell'):
                        if hasattr(shell, 'start_interactive_shell_loop'):
                            # Don't display the output message, just start the loop directly
                            shell.start_interactive_shell_loop()
                            continue
                    
                    # Display output (only if not starting interactive shell)
                    if result and result.get('output'):
                        output = result['output']
                        # Ensure output ends with newline if it doesn't already
                        if output and not output.endswith('\n'):
                            output += '\n'
                        print_info(output)
                    
                    if result and result.get('error'):
                        print_error(result['error'])
                    
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
            
            return True
            
        except Exception as e:
            print_error(f"Error starting interactive session: {str(e)}")
            return False
    
    def _show_shell_help(self, shell):
        """Show help for shell commands"""
        try:
            if hasattr(shell, 'get_available_commands'):
                commands = shell.get_available_commands()
                print_info("Available shell commands:")
                for cmd in commands:
                    print_info(f"  {cmd}")
            else:
                print_info("No help available for this shell type")
        except Exception as e:
            print_error(f"Error showing shell help: {str(e)}")
    
