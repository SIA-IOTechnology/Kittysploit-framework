from core.framework.base_module import BaseModule
from core.framework.enums import Handler, SessionType
from core.output_handler import print_success, print_status, print_error, print_info, print_warning
from core.framework.option.option_integer import OptInteger
from typing import Optional, Dict, Any, List
import threading
import time
import socket
import uuid

class Listener(BaseModule):
    """Base class for listener modules with enhanced session management"""

    TYPE_MODULE = "listener"
    
    timeout = OptInteger(30, "Connection timeout in seconds", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "listener"
        
        # Listener state management
        self.running = False
        self.stop_flag = threading.Event()
        self.listener_thread = None
        self.connections = {}  # Store active connections by conn_id (target:port)
        self._session_connections = {}  # Store connections by session_id for easy lookup
        self.session_count = 0
        
        # Common listener options
#        self.lhost = OptString("127.0.0.1", "Local host for reverse listeners", False)
#        self.lport = OptPort(4444, "Local port for reverse listeners", False)
#        self.rhost = OptString("", "Remote host for bind listeners", False)
#        self.rport = OptPort(4444, "Remote port for bind listeners", False)
#        self.handler = OptChoice("reverse", "Handler type", False, ["reverse", "bind"])
#        self.session_type = OptChoice("shell", "Session type", False, ["shell", "meterpreter", "http", "https"])
#        self.timeout = OptPort(30, "Connection timeout in seconds", False)
#        self.auto_start = OptBool(True, "Automatically start listener", False)
        
        # Listener configuration
        self.listener_id = str(uuid.uuid4())
        self.start_time = None
        self.stats = {
            'connections_received': 0,
            'sessions_created': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'uptime': 0
        }

    def run(self):
        """Run the listener - must be implemented by derived classes"""
        raise NotImplementedError("Listener modules must implement the run() method")
    
    def run_with_auto_session(self):
        """Run the listener with automatic session management - calls run() and handles session creation"""
        try:
            # Call the module's run method
            result = self.run()
            
            # If result is a tuple with (connection, target, port), create session automatically
            if isinstance(result, tuple) and len(result) >= 3:
                connection, target, port = result[0], result[1], result[2]
                additional_data = result[3] if len(result) > 3 else {}
                
                # Create session automatically using __info__ data
                session_id = self._create_session_from_connection_data(
                    connection, target, port, additional_data
                )
                
                if session_id:
                    print_success(f"Session {session_id} created automatically")
                    return session_id
                else:
                    print_error("Failed to create session automatically")
                    return False
            
            # If result is a session ID (string), return it
            elif isinstance(result, str):
                return result
            
            # If result is boolean, return it
            elif isinstance(result, bool):
                return result
            
            # If result is a connection object, try to create session
            elif hasattr(result, 'send') or hasattr(result, 'recv'):
                # Try to determine target and port from connection
                target = getattr(self, 'rhost', 'unknown')
                port = getattr(self, 'rport', 0)
                
                session_id = self._create_session_from_connection_data(
                    result, target, port, {}
                )
                
                if session_id:
                    print_success(f"Session {session_id} created automatically")
                    return session_id
                else:
                    return False
            
            # Unknown result type
            else:
                print_warning(f"Unknown result type from run(): {type(result)}")
                return bool(result)
                
        except Exception as e:
            print_error(f"Error in run_with_auto_session: {e}")
            return False
    
    def _create_session_from_connection_data(self, connection, target, port, additional_data):
        """Helper method to create session from connection data"""
        try:
            # Extract protocol from __info__ if available
            protocol = 'tcp'  # default
            if hasattr(self, '__info__') and 'protocol' in self.__info__:
                protocol = self.__info__['protocol']
            elif 'socket' in str(type(connection)).lower():
                protocol = 'tcp'
            elif 'ssh' in str(type(connection)).lower():
                protocol = 'ssh'
            elif 'http' in str(type(connection)).lower():
                protocol = 'http'
            
            # Get handler and session_type from __info__ if available, otherwise use instance attributes
            handler = self.handler
            if hasattr(self, '__info__') and 'handler' in self.__info__:
                handler_info = self.__info__['handler']
                # Extract value from enum or use directly if string
                if hasattr(handler_info, 'value'):
                    handler = handler_info.value
                elif hasattr(handler_info, 'name'):
                    handler = handler_info.name.lower()
                else:
                    handler = str(handler_info).lower()
            elif hasattr(self.handler, 'value'):
                handler = self.handler.value
            else:
                handler = str(self.handler)
            
            session_type = self.session_type
            if hasattr(self, '__info__') and 'session_type' in self.__info__:
                session_type_info = self.__info__['session_type']
                # Extract value from enum or use directly if string
                if hasattr(session_type_info, 'value'):
                    session_type = session_type_info.value
                elif hasattr(session_type_info, 'name'):
                    session_type = session_type_info.name.lower()
                else:
                    session_type = str(session_type_info).lower()
            elif hasattr(self.session_type, 'value'):
                session_type = self.session_type.value
            else:
                session_type = str(self.session_type)
            
            # Prepare session data (without non-serializable objects for database)
            # Store connection metadata only, not the connection object itself
            session_data = {
                'address': (target, port),
                'connection_time': time.time(),
                'protocol': protocol,
                'listener_type': self.name.lower().replace(' ', '_'),
                'handler': handler,
                'session_type': session_type
            }
            
            # Add connection type info if available
            connection_type = str(type(connection).__name__)
            session_data['connection_type'] = connection_type
            
            # Add username if available from listener
            if hasattr(self, 'username'):
                username_value = self.username.value if hasattr(self.username, 'value') else str(self.username)
                session_data['username'] = username_value
            
            # Add additional data if provided (but filter out non-serializable objects)
            if additional_data:
                for key, value in additional_data.items():
                    # Only include serializable data
                    try:
                        import json
                        json.dumps(value)
                        session_data[key] = value
                    except (TypeError, ValueError):
                        # Skip non-serializable objects
                        pass
            
            # Create session
            session_id = self._create_session(handler, target, port, session_data)
            
            if session_id:
                # Store connection object separately in memory (not in database)
                conn_id = f"{target}:{port}"
                self.connections[conn_id] = connection
                
                # Also store mapping from session_id to connection for easy lookup
                self._session_connections[session_id] = connection
                
                self.stats['connections_received'] += 1
                
                return session_id
            else:
                return None
                
        except Exception as e:
            print_error(f"Error creating session from connection data: {e}")
            return None

    def start(self):
        """Start the listener in a background thread"""
        try:
            if self.running:
                print_warning("Listener is already running")
                return True
            
            print_info(f"Starting {self.name} listener...")
            print_info(f"Handler: {self.handler}")
            print_info(f"Session type: {self.session_type}")
            
            if self.handler == "reverse":
                print_info(f"Listening on {self.lhost}:{self.lport}")
            elif self.handler == "bind":
                print_info(f"Connecting to {self.rhost}:{self.rport}")
            
            # Start listener in background thread
            self.listener_thread = threading.Thread(target=self._run_listener, daemon=True)
            self.listener_thread.start()
            
            # Wait a moment for listener to start
            time.sleep(1)
            
            self.running = True
            self.start_time = time.time()
            print_success(f"{self.name} listener started successfully")
            return True
            
        except Exception as e:
            print_error(f"Failed to start listener: {e}")
            return False

    def stop(self):
        """Stop the listener"""
        try:
            if not self.running:
                print_warning("Listener is not running")
                return True
            
            print_info(f"Stopping {self.name} listener...")
            
            # Set stop flag
            self.stop_flag.set()
            self.running = False
            
            # Wait for listener thread to finish
            if self.listener_thread and self.listener_thread.is_alive():
                self.listener_thread.join(timeout=5)
            
            # Close all connections
            self._close_all_connections()
            
            print_success(f"{self.name} listener stopped")
            return True
            
        except Exception as e:
            print_error(f"Error stopping listener: {e}")
            return False

    def _run_listener(self):
        """Run the listener in background thread"""
        try:
            # Call the actual listener implementation
            result = self.run()
            
            # Handle the result automatically
            if result:
                self._handle_listener_result(result)
            else:
                print_info("Listener completed without session")
            
        except Exception as e:
            print_error(f"Listener error: {e}")
        finally:
            self.running = False
    
    def _handle_listener_result(self, result):
        """Handle the result from listener implementation"""
        try:
            if isinstance(result, tuple) and len(result) >= 2:
                # Result format: (handler, target, port, session_data)
                handler, target, port = result[0], result[1], result[2]
                session_data = result[3] if len(result) > 3 else {}
                
                # Create session automatically
                self._create_session(handler, target, port, session_data)
            elif isinstance(result, dict):
                # Result format: dict with session information
                handler = result.get('handler', self.handler)
                target = result.get('target', self.lhost if self.handler == 'reverse' else self.rhost)
                port = result.get('port', self.lport if self.handler == 'reverse' else self.rport)
                session_data = result.get('session_data', {})
                
                # Create session automatically
                self._create_session(handler, target, port, session_data)
            else:
                print_warning("Unknown result format from listener")
                
        except Exception as e:
            print_error(f"Error handling listener result: {e}")

    def _create_session(self, handler: str, target: str, port: int, session_data: Dict[str, Any] = None):
        """Create a new session from listener connection"""
        try:
            if not session_data:
                session_data = {}
            
            # Add additional metadata to session_data
            session_data['handler'] = handler
            session_data['listener_id'] = self.listener_id
            session_data['listener_module'] = self.name
            session_data['created_at'] = time.time()
            
            # Get session_type from session_data if available, otherwise use default
            session_type_str = session_data.get('session_type', 'ssh')
            if isinstance(session_type_str, SessionType):
                # Extract value from enum
                if hasattr(session_type_str, 'value'):
                    session_type_str = session_type_str.value
                elif hasattr(session_type_str, 'name'):
                    session_type_str = session_type_str.name.lower()
                else:
                    session_type_str = str(session_type_str).lower()
            
            # Register this listener in framework's active listeners
            if self.framework and hasattr(self.framework, 'active_listeners'):
                self.framework.active_listeners[self.listener_id] = self
            
            # Create session using SessionManager if available
            if self.framework and hasattr(self.framework, 'session_manager'):
                session_id = self.framework.session_manager.create_session(
                    host=target,
                    port=port,
                    session_type=session_type_str,
                    data=session_data
                )
            else:
                # Fallback: generate session ID manually
                session_id = str(uuid.uuid4())
            
            # Update stats
            self.stats['sessions_created'] += 1
            self.session_count += 1
            
            print_success(f"Session created: {session_id}")
            print_info(f"Handler: {handler}, Target: {target}:{port}")
            
            return session_id
            
        except Exception as e:
            print_error(f"Failed to create session: {e}")
            return None

    def _close_all_connections(self):
        """Close all active connections"""
        try:
            for conn_id, connection in self.connections.items():
                try:
                    if hasattr(connection, 'close'):
                        connection.close()
                except:
                    pass
            
            self.connections.clear()
            print_info("All connections closed")
            
        except Exception as e:
            print_error(f"Error closing connections: {e}")

    def get_status(self):
        """Get current listener status"""
        uptime = 0
        if self.start_time:
            uptime = time.time() - self.start_time
        
        return {
            'running': self.running,
            'listener_id': self.listener_id,
            'handler': self.handler,
            'session_type': self.session_type,
            'uptime': uptime,
            'stats': self.stats.copy(),
            'connections': len(self.connections)
        }

    def get_stats(self):
        """Get listener statistics"""
        return self.stats.copy()

    def reset_stats(self):
        """Reset listener statistics"""
        self.stats = {
            'connections_received': 0,
            'sessions_created': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'uptime': 0
        }

    def is_running(self):
        """Check if listener is running"""
        return self.running

    def wait_for_connection(self, timeout=60):
        """Wait for a connection to the listener"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.running:
                break
            if self.session_count > 0:
                return True
            time.sleep(1)
        return False

    def shutdown(self):
        """Shutdown the listener gracefully"""
        return self.stop()

    def create_session_from_connection(self, connection, address, additional_data=None):
        """Helper method to create session from connection - to be called by derived classes"""
        try:
            # Determine target and port based on handler type
            if self.is_reverse_handler():
                target = address[0] if address else self.lhost
                port = address[1] if address else self.lport
            else:  # bind
                target = self.rhost
                port = self.rport
            
            # Prepare session data (without non-serializable objects like socket)
            session_data = {
                'address': (target, port),  # Store as tuple, not socket object
                'connection_time': time.time(),
                'protocol': 'tcp',
                'listener_type': self.name.lower().replace(' ', '_'),
            }
            
            # Get handler value properly
            handler_value = self.handler
            if hasattr(handler_value, 'value'):
                handler_value = handler_value.value
            elif hasattr(handler_value, 'name'):
                handler_value = handler_value.name.lower()
            else:
                handler_value = str(handler_value).lower()
            session_data['handler'] = handler_value
            
            # Add additional data if provided (but filter out non-serializable objects)
            if additional_data:
                for key, value in additional_data.items():
                    # Only include serializable data
                    try:
                        import json
                        json.dumps(value)
                        session_data[key] = value
                    except (TypeError, ValueError):
                        # Skip non-serializable objects (like socket)
                        pass
            
            # Create session
            session_id = self._create_session(handler_value, target, port, session_data)
            
            if session_id:
                # Store connection object separately in memory (not in database)
                conn_id = f"{target}:{port}"
                self.connections[conn_id] = connection
                
                # Also store mapping from session_id to connection for easy lookup
                self._session_connections[session_id] = connection
                
                self.stats['connections_received'] += 1
                
                print_success(f"Session {session_id} created for {target}:{port}")
                return session_id
            else:
                print_error("Failed to create session")
                return None
                
        except Exception as e:
            print_error(f"Error creating session from connection: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_simple_session(self, target=None, port=None, additional_data=None):
        """Helper method to create a simple session - to be called by derived classes"""
        try:
            # Use provided values or defaults
            if target is None:
                target = self.lhost if self.is_reverse_handler() else self.rhost
            if port is None:
                port = self.lport if self.is_reverse_handler() else self.rport
            
            # Prepare session data
            session_data = {
                'connection_time': time.time(),
                'protocol': 'tcp',
                'listener_type': self.name.lower().replace(' ', '_'),
                'handler': self.handler
            }
            
            # Add additional data if provided
            if additional_data:
                session_data.update(additional_data)
            
            # Create session
            session_id = self._create_session(self.handler, target, port, session_data)
            
            if session_id:
                self.stats['connections_received'] += 1
                print_success(f"Session {session_id} created for {target}:{port}")
                return session_id
            else:
                print_error("Failed to create session")
                return None
                
        except Exception as e:
            print_error(f"Error creating simple session: {e}")
            return None
    
    def connect_and_create_session(self, target=None, port=None, additional_data=None, welcome_messages=None):
        """Helper method to connect and create session in one operation - for bind listeners"""
        try:
            # Use provided values or defaults
            if target is None:
                target = self.rhost
            if port is None:
                port = self.rport
                
            print_info(f"Connecting to {target}:{port}")
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            
            # Try to connect
            sock.connect((target, port))
            print_success(f"Connected to {target}:{port}")
            
            # Prepare session data
            session_data = {
                'connection': sock,
                'address': (target, port),
                'connection_time': time.time(),
                'protocol': 'tcp',
                'listener_type': self.name.lower().replace(' ', '_'),
                'handler': self.handler,
                'connection_type': 'bind'
            }
            
            # Add additional data if provided
            if additional_data:
                session_data.update(additional_data)
            
            # Create session
            session_id = self._create_session(self.handler, target, port, session_data)
            
            if session_id:
                # Store connection
                conn_id = f"{target}:{port}"
                self.connections[conn_id] = sock
                self.stats['connections_received'] += 1
                
                # Send welcome messages if provided
                if welcome_messages:
                    for message in welcome_messages:
                        self.send_to_connection(sock, message)
                
                print_success(f"Session {session_id} created for {target}:{port}")
                return session_id
            else:
                print_error("Failed to create session")
                sock.close()
                return None
                
        except ConnectionRefusedError:
            print_error(f"Connection refused to {target}:{port}")
            return None
        except socket.timeout:
            print_error(f"Connection timeout to {target}:{port}")
            return None
        except Exception as e:
            print_error(f"Connection error: {e}")
            return None
    
    def listen_and_create_sessions(self, target=None, port=None, additional_data=None, welcome_messages=None, max_connections=5):
        """Helper method to listen and create sessions for reverse listeners"""
        try:
            # Use provided values or defaults
            if target is None:
                target = self.lhost
            if port is None:
                port = self.lport
                
            print_info(f"Starting reverse listener on {target}:{port}")
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)  # Set timeout for non-blocking behavior
            sock.bind((target, port))
            sock.listen(max_connections)
            
            print_success(f"Listening on {target}:{port}")
            print_info("Waiting for connections...")
            print_info("Press Ctrl+C to stop the listener")
            
            session_count = 0
            
            while not self.stop_flag.is_set():
                try:
                    # Accept connection
                    client_socket, address = sock.accept()
                    session_count += 1
                    
                    print_success(f"Connection received from {address[0]}:{address[1]} (Session #{session_count})")
                    
                    # Prepare session data
                    session_data = {
                        'connection': client_socket,
                        'address': address,
                        'connection_time': time.time(),
                        'protocol': 'tcp',
                        'listener_type': self.name.lower().replace(' ', '_'),
                        'handler': self.handler,
                        'connection_type': 'reverse'
                    }
                    
                    # Add additional data if provided
                    if additional_data:
                        session_data.update(additional_data)
                    
                    # Create session
                    session_id = self._create_session(self.handler, address[0], address[1], session_data)
                    
                    if session_id:
                        # Store connection
                        conn_id = f"{address[0]}:{address[1]}"
                        self.connections[conn_id] = client_socket
                        self.stats['connections_received'] += 1
                        
                        # Send welcome messages if provided
                        if welcome_messages:
                            for message in welcome_messages:
                                self.send_to_connection(client_socket, message)
                        
                        print_success(f"Session {session_id} created for {address[0]}:{address[1]}")
                        
                        # Handle connection in separate thread
                        connection_thread = threading.Thread(
                            target=self._handle_connection,
                            args=(client_socket, address, session_id),
                            daemon=True
                        )
                        connection_thread.start()
                    
                except socket.timeout:
                    # Timeout occurred, continue listening
                    continue
                except KeyboardInterrupt:
                    print_info("\n[!] Interrupted by user")
                    break
                except Exception as e:
                    if not self.stop_flag.is_set():
                        print_error(f"Error accepting connection: {e}")
                    break
            
            # Clean up
            sock.close()
            print_info(f"Listener stopped. Total sessions created: {session_count}")
            return True
                
        except Exception as e:
            print_error(f"Listener error: {e}")
            return False
    
    def _handle_connection(self, client_socket, address, session_id):
        """Handle individual client connection - can be overridden by derived classes"""
        try:
            print_info(f"Handling connection from {address[0]}:{address[1]} (Session: {session_id})")
            
            # Simple connection handling - derived classes can override this
            # Keep connection alive for a while
            time.sleep(1)
            
        except Exception as e:
            print_error(f"Error handling connection: {e}")
        finally:
            # Clean up connection
            try:
                client_socket.close()
            except:
                pass
    
    def test_connection(self, target=None, port=None, timeout=5):
        """Helper method to test if a remote host is reachable"""
        try:
            # Use provided values or defaults
            if target is None:
                target = self.rhost if self.handler == "bind" else self.lhost
            if port is None:
                port = self.rport if self.handler == "bind" else self.lport
                
            print_info(f"Testing connection to {target}:{port}")
            
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(timeout)
            
            try:
                test_sock.connect((target, port))
                test_sock.close()
                print_success(f"Remote host {target}:{port} is reachable")
                return True
            except ConnectionRefusedError:
                print_error(f"Connection refused to {target}:{port}")
                return False
            except socket.timeout:
                print_error(f"Connection timeout to {target}:{port}")
                return False
            except Exception as e:
                print_error(f"Connection test failed: {e}")
                return False
                
        except Exception as e:
            print_error(f"Error testing connection: {e}")
            return False
    
    def connect_ssh_and_create_session(self, target=None, port=None, username=None, password=None, additional_data=None, welcome_messages=None):
        """Helper method to connect via SSH and create session in one operation"""
        try:
            import paramiko
            
            # Use provided values or defaults
            if target is None:
                target = self.rhost
            if port is None:
                port = self.rport
            if username is None:
                username = getattr(self, 'username', 'root')
            if password is None:
                password = getattr(self, 'password', '')
                
            print_info(f"Connecting to SSH server {target}:{port} as {username}")
            
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to SSH server
            ssh_client.connect(target, port, username, password)
            print_success(f"Connected to SSH server {target}:{port}")
            
            # Prepare session data
            session_data = {
                'connection': ssh_client,
                'address': (target, port),
                'connection_time': time.time(),
                'protocol': 'ssh',
                'listener_type': self.name.lower().replace(' ', '_'),
                'handler': self.handler,
                'connection_type': 'bind',
                'username': username,
                'authentication_method': 'password'
            }
            
            # Add additional data if provided
            if additional_data:
                session_data.update(additional_data)
            
            # Create session
            session_id = self._create_session(self.handler, target, port, session_data)
            
            if session_id:
                # Store connection
                conn_id = f"{target}:{port}"
                self.connections[conn_id] = ssh_client
                self.stats['connections_received'] += 1
                
                # Send welcome messages if provided
                if welcome_messages:
                    for message in welcome_messages:
                        # For SSH, we need to execute commands
                        stdin, stdout, stderr = ssh_client.exec_command(message.strip())
                        # Read output
                        output = stdout.read().decode()
                        if output:
                            print_info(f"SSH Output: {output}")
                
                print_success(f"SSH Session {session_id} created for {target}:{port}")
                return session_id
            else:
                print_error("Failed to create SSH session")
                ssh_client.close()
                return None
                
        except ImportError:
            print_error("paramiko library not installed. Install with: pip install paramiko")
            return None
        except paramiko.AuthenticationException:
            print_error(f"SSH authentication failed for {username}@{target}:{port}")
            return None
        except paramiko.SSHException as e:
            print_error(f"SSH connection error: {e}")
            return None
        except Exception as e:
            print_error(f"SSH connection error: {e}")
            return None
    
    def send_to_connection(self, connection, data):
        """Helper method to send data to a connection"""
        try:
            if hasattr(connection, 'send'):
                connection.send(data.encode() if isinstance(data, str) else data)
                self.stats['bytes_sent'] += len(data)
                return True
            else:
                print_error("Connection does not support send method")
                return False
        except Exception as e:
            print_error(f"Error sending data: {e}")
            return False
    
    def receive_from_connection(self, connection, buffer_size=1024):
        """Helper method to receive data from a connection"""
        try:
            if hasattr(connection, 'recv'):
                data = connection.recv(buffer_size)
                self.stats['bytes_received'] += len(data)
                return data
            else:
                print_error("Connection does not support recv method")
                return None
        except Exception as e:
            print_error(f"Error receiving data: {e}")
            return None

    def is_reverse_handler(self):
        """Check if handler is reverse"""
        return self.handler == "reverse" or self.handler == Handler.REVERSE
    
    def is_bind_handler(self):
        """Check if handler is bind"""
        return self.handler == "bind" or self.handler == Handler.BIND
    
    def is_shell_session(self):
        """Check if session type is shell"""
        return self.session_type == "shell" or self.session_type == SessionType.SHELL
    
    def is_meterpreter_session(self):
        """Check if session type is meterpreter"""
        return self.session_type == "meterpreter" or self.session_type == SessionType.METERPRETER
    
    def is_http_session(self):
        """Check if session type is http"""
        return self.session_type == "http" or self.session_type == SessionType.HTTP
    
    def is_https_session(self):
        """Check if session type is https"""
        return self.session_type == "https" or self.session_type == SessionType.HTTPS

    def default_options(self):
        """Return default options for the listener"""
        return {
            'lhost': self.lhost,
            'lport': self.lport,
            'rhost': self.rhost,
            'rport': self.rport,
            'handler': self.handler,
            'session_type': self.session_type,
            'timeout': self.timeout,
            'auto_start': self.auto_start
        }
