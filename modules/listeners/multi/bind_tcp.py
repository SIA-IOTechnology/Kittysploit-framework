from kittysploit import *
import socket

class Module(Listener):
    
    __info__ = {
        "name": "bind shell tcp",
        "handler": Handler.BIND,
        "module": "listeners/multi/bind_tcp",
        "session_type": SessionType.SHELL,
    }
    
    rhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
    rport = OptPort(4444, "Target HTTP port", True)
    
    def run(self):
        try:
            print_status(f"Trying connect to {self.rhost}:{self.rport}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.sock.connect((self.rhost, self.rport))
                return (self.sock, self.rhost, self.rport)
            except ConnectionRefusedError:
                print_error("Connection refused")
                return False
        
        except KeyboardInterrupt:
            return False
        except OSError as e:
            return False
    
    def shutdown(self):
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except OSError as e:
            pass