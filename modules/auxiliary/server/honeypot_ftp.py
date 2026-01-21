from kittysploit import *
from lib.protocols.tcp.tcp_server import Tcp_server
import socket
import threading
import datetime
import os

class Module(Auxiliary, Tcp_server):

    __info__ = {
        'name': 'FTP Honeypot Server',
        'description': 'Advanced FTP honeypot that simulates a real FTP server and logs intrusion attempts',
        'author': 'KittySploit Team',
    }

    ftp_banner = OptString("220 ProFTPD 1.3.5 Server (Debian)", "FTP banner", True)
    ftp_port = OptPort(21, "FTP port to bind", True)
    log_file = OptString("ftp_honeypot.log", "Log file path", True, advanced=True)
    fake_users = OptString("admin,root,ftp,user,test", "Comma-separated list of fake accepted usernames", True, advanced=True)
    max_connections = OptInteger(50, "Maximum concurrent connections", True, advanced=True)

    def run(self):
        # Initialize connection tracking
        self.active_connections = 0
        self.lock = threading.Lock()
        
        print_info(f"Starting FTP Honeypot on 0.0.0.0:{self.ftp_port}")
        print_info(f"Logs will be saved to: {self.log_file}")
        
        # Create log file if it doesn't exist
        self._log_event("SYSTEM", "0.0.0.0", "Honeypot started")
        
        try:
            # Use short timeout (1s) for quick response to Ctrl+C
            server = self.start_tcp_server("0.0.0.0", self.ftp_port, timeout=1)
            server.serve_forever(self._handle_client_wrapper)
        except KeyboardInterrupt:
            print_warning("\nStopping FTP Honeypot...")
            self._log_event("SYSTEM", "0.0.0.0", "Honeypot stopped")
            print_success("Honeypot stopped successfully")
        except PermissionError:
            print_error(f"Permission denied: Cannot bind to port {self.ftp_port}")
            print_info("Try running with administrator/root privileges or use a port > 1024")
        except Exception as e:
            print_error(f"Honeypot error: {e}")
            self._log_event("ERROR", "0.0.0.0", f"Honeypot error: {e}")

    def _handle_client_wrapper(self, server, client_socket, address):
        """Wrapper to handle client in the serve_forever context"""
        with self.lock:
            if self.active_connections >= self.max_connections:
                print_warning(f"Max connections reached, rejecting {address[0]}")
                client_socket.close()
                return
            self.active_connections += 1
        
        try:
            # Set longer timeout for client interactions (60 seconds)
            client_socket.settimeout(60)
            self.handle_client(client_socket, address)
        finally:
            with self.lock:
                self.active_connections -= 1

    def handle_client(self, client, address):
        """Handle FTP client interactions"""
        ip = address[0]
        port = address[1]
        
        # Collect client info
        hostname = self._get_hostname(ip)
        
        print_success(f"[NEW CONNECTION] {ip}:{port} ({hostname})")
        self._log_event("CONNECT", ip, f"New connection from {hostname}")
        
        # Session state
        session = {
            'authenticated': False,
            'username': None,
            'current_dir': '/'
        }
        
        try:
            # Send banner
            self._send_response(client, self.ftp_banner)
            
            # Main command loop
            while True:
                try:
                    data = client.recv(4096)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    if not command:
                        continue
                    
                    print_info(f"[{ip}] Command: {command}")
                    self._log_event("COMMAND", ip, command)
                    
                    # Process FTP command
                    if not self._process_command(client, command, session, ip):
                        break
                        
                except socket.timeout:
                    self._send_response(client, "421 Timeout - closing connection")
                    break
                except Exception as e:
                    print_error(f"[{ip}] Error: {e}")
                    break
                    
        except Exception as e:
            print_error(f"[{ip}] Client handler error: {e}")
        finally:
            print_status(f"[DISCONNECT] {ip}:{port}")
            self._log_event("DISCONNECT", ip, "Connection closed")
            try:
                client.close()
            except:
                pass

    def _process_command(self, client, command, session, ip):
        """Process FTP commands"""
        cmd_upper = command.upper()
        parts = command.split(None, 1)
        cmd = parts[0].upper() if parts else ""
        arg = parts[1] if len(parts) > 1 else ""
        
        # USER command
        if cmd == "USER":
            session['username'] = arg
            session['authenticated'] = False
            print_warning(f"[{ip}] Login attempt - Username: {arg}")
            self._log_event("AUTH_ATTEMPT", ip, f"Username: {arg}")
            self._send_response(client, "331 Password required for " + arg)
        
        # PASS command
        elif cmd == "PASS":
            username = session.get('username', 'unknown')
            print_warning(f"[{ip}] Login attempt - Username: {username}, Password: {arg}")
            self._log_event("AUTH_ATTEMPT", ip, f"Username: {username}, Password: {arg}")
            
            # Simulate successful login for specific users
            fake_users_list = [u.strip() for u in self.fake_users.split(',')]
            if username.lower() in fake_users_list:
                session['authenticated'] = True
                print_success(f"[{ip}] Fake authentication successful for: {username}")
                self._send_response(client, "230 User logged in, proceed")
            else:
                self._send_response(client, "530 Login incorrect")
        
        # SYST command
        elif cmd == "SYST":
            self._send_response(client, "215 UNIX Type: L8")
        
        # PWD command
        elif cmd == "PWD":
            if session['authenticated']:
                self._send_response(client, f'257 "{session["current_dir"]}" is current directory')
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # CWD command
        elif cmd == "CWD":
            if session['authenticated']:
                session['current_dir'] = arg if arg else '/'
                self._send_response(client, f"250 CWD command successful")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # LIST/NLST commands
        elif cmd in ["LIST", "NLST"]:
            if session['authenticated']:
                self._send_response(client, "150 Opening ASCII mode data connection for file list")
                self._send_response(client, "226 Transfer complete")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # TYPE command
        elif cmd == "TYPE":
            self._send_response(client, f"200 Type set to {arg}")
        
        # PASV command (passive mode)
        elif cmd == "PASV":
            if session['authenticated']:
                self._send_response(client, "227 Entering Passive Mode (127,0,0,1,19,136)")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # PORT command (active mode)
        elif cmd == "PORT":
            if session['authenticated']:
                self._send_response(client, "200 PORT command successful")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # RETR command (download)
        elif cmd == "RETR":
            if session['authenticated']:
                print_warning(f"[{ip}] Attempted to download: {arg}")
                self._log_event("FILE_ACCESS", ip, f"Download attempt: {arg}")
                self._send_response(client, "550 File not found")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # STOR command (upload)
        elif cmd == "STOR":
            if session['authenticated']:
                print_warning(f"[{ip}] Attempted to upload: {arg}")
                self._log_event("FILE_ACCESS", ip, f"Upload attempt: {arg}")
                self._send_response(client, "550 Permission denied")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # DELE command (delete)
        elif cmd == "DELE":
            if session['authenticated']:
                print_warning(f"[{ip}] Attempted to delete: {arg}")
                self._log_event("FILE_ACCESS", ip, f"Delete attempt: {arg}")
                self._send_response(client, "550 Permission denied")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # MKD command (make directory)
        elif cmd == "MKD":
            if session['authenticated']:
                self._send_response(client, "550 Permission denied")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # RMD command (remove directory)
        elif cmd == "RMD":
            if session['authenticated']:
                self._send_response(client, "550 Permission denied")
            else:
                self._send_response(client, "530 Please login with USER and PASS")
        
        # NOOP command
        elif cmd == "NOOP":
            self._send_response(client, "200 NOOP command successful")
        
        # QUIT command
        elif cmd == "QUIT":
            self._send_response(client, "221 Goodbye")
            return False  # Close connection
        
        # HELP command
        elif cmd == "HELP":
            self._send_response(client, "214 The following commands are recognized:")
            self._send_response(client, " USER PASS SYST PWD CWD LIST TYPE PASV PORT RETR STOR QUIT")
            self._send_response(client, "214 Help OK")
        
        # Unknown command
        else:
            self._send_response(client, f"500 Unknown command: {cmd}")
        
        return True  # Continue connection

    def _send_response(self, client, message):
        """Send FTP response to client"""
        try:
            if not message.endswith('\r\n'):
                message += '\r\n'
            client.send(message.encode('utf-8'))
        except Exception as e:
            print_error(f"Failed to send response: {e}")

    def _get_hostname(self, ip):
        """Get hostname from IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "unknown"

    def _log_event(self, event_type, ip, details):
        """Log honeypot events to file"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] [{event_type}] [{ip}] {details}\n"
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print_error(f"Failed to write log: {e}")
