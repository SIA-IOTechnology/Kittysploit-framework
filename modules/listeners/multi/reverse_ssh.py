from kittysploit import *
import paramiko
import threading
import socket
from io import StringIO


class Module(Listener):

	__info__ = {
		"name": "Create ssh server",
		"description": "Create a ssh server and listen for connections",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SSH
	}
	
	lhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
	lport = OptPort(2222, "Target HTTP port", True)
	username = OptString("ubuntu", "username", True)
	password = OptString("pwned", "password", True)
	
	wait_valid_auth = OptBool(True, "Stay listening if credentials are bad", True, True)

	def generate_rsa_key(self):
		key = paramiko.RSAKey.generate(2048)
		key_str = StringIO()
		key.write_private_key(key_str)
		return key, key_str.getvalue()

	def run(self):
		server_host_key, server_host_key_str = self.generate_rsa_key()
		print_status("Generated RSA Key:\n", server_host_key_str)
		
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)		
		try:
			server_socket.bind((self.lhost, self.lport))
		except:
			print_error(f"Bind Error for SSH Server using {self.lhost}:{server_socket.getsockname()[1]}")
			return False
		print_success(f"Bind Success for SSH Server using {self.lhost}:{server_socket.getsockname()[1]}")
		while True:

			server_socket.listen(100)
			print_status("Listening")

			client_socket, addr = server_socket.accept()
			print_status(f"Incoming TCP Connection from {addr[0]}:{addr[1]}")

			try:
				ssh_session = paramiko.Transport(client_socket)
				ssh_session.add_server_key(server_host_key)
				server = Server(self.username, self.password)
				try:
					ssh_session.start_server(server=server)
				except paramiko.SSHException:
					print_error("SSH Parameters Negotiation Failed")
					return False
				print_status("SSH Parameters Negotiation Succeeded")
				print_status("Authenticating")
				ssh_channel = ssh_session.accept(20)
				if ssh_channel == None or not ssh_channel.active:
					print_status("SSH Client Authentication Failure")
					print_error("Bad credentials")
					if self.wait_valid_auth:
						continue
					else:
						break
	#				ssh_session.close()
				else:
					print_status("SSH Client Authenticated")
					if not ssh_channel.closed:
						return (ssh_channel, addr[0], addr[1])
					else:
						return False
			except:
				print_error("Error closing SSH session")
				return False

class Server(paramiko.ServerInterface):
	def __init__(self, username, password):
		self.event = threading.Event()
		self.username = username
		self.password = password
	def check_auth_password(self, username, password):
		if username == self.username and password == self.password:
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED
	def check_channel_request(self, kind, chanid):
		if kind == "session":
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
