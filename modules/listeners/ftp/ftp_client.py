from kittysploit import *
from ftplib import FTP

class Module(Listener):
	
	__info__ = {
		'name': 'FTP Listener',
		'description': 'FTP client listener - connects to FTP server and creates interactive FTP shell session',
		'author': 'KittySploit Team',
		'handler': Handler.BIND,
		'session_type': SessionType.FTP,
	}
	
	host = OptString("127.0.0.1", "FTP server host", True)
	port = OptPort(21, "FTP server port", True)
	username = OptString("anonymous", "FTP username", True)
	password = OptString("", "FTP password", False)

	def run(self):
		"""Connect to FTP server and create session"""
		try:
			print_status(f"Connecting to FTP server {self.host}:{self.port}...")
			
			# Connect to FTP server
			ftp = FTP()
			ftp.connect(self.host, int(self.port))
			ftp.login(self.username, self.password)
			
			print_success(f"Connected to FTP server as {self.username}")
			
			# Store connection and credentials for the shell
			additional_data = {
				'host': self.host,
				'port': int(self.port),
				'username': self.username,
				'password': self.password,
				'connection': ftp  # Store FTP connection object
			}
			
			# Return connection, target, port, and additional data
			return (ftp, self.host, int(self.port), additional_data)
			
		except Exception as e:
			print_error(f"FTP connection failed: {e}")
			return False

