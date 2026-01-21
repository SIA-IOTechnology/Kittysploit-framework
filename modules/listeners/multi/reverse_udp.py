from kittysploit import *
import socket

class Module(Listener):
	__info__ = {
		"name": "Reverse UDP Listener",
		"description": "Create a UDP server and listen for connections",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL
	}
	
	lhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
	lport = OptPort(4444, "Target UDP port", True)

	def run(self):
		try:
			print_status(f"Start server on {self.lhost}:{self.lport}")
			print_status("Waiting connection...") 
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.sock.bind((self.lhost, self.lport))
			self.sock.listen(5)
			client, address = self.sock.accept()
			return (client, address[0], address[1], {'connection_type': 'reverse', 'protocol': 'udp'})
		except KeyboardInterrupt:
			return False
		except OSError:
			print_error("Port busy")
			return False

	def shutdown(self):
		try:
			if self.sock:
				self.sock.shutdown(socket.SHUT_RDWR)
				self.sock.close()
		except OSError as e:
			pass