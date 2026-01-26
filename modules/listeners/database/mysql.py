from kittysploit import *
import pymysql

class Module(Listener):
	
	__info__ = {
		'name': 'MySQL Listener',
		'description': 'MySQL database listener - creates interactive MySQL shell session ',
		'author': 'KittySploit Team',
		'handler': Handler.BIND,
		'session_type': SessionType.MYSQL,
	}
	
	host = OptString("127.0.0.1", "MySQL server host", True)
	port = OptPort(3306, "MySQL server port", True)
	username = OptString("root", "MySQL username", True)
	password = OptString("", "MySQL password", False)
	database = OptString("", "Default database (optional)", False)

	def run(self):
		"""Connect to MySQL server and create session"""
		try:
			print_status(f"Connecting to MySQL server {self.host}:{self.port}...")
			
			# Test connection
			connection = pymysql.connect(
				host=self.host,
				port=int(self.port),
				user=self.username,
				password=self.password,
				database=self.database if self.database else None,
				connect_timeout=10
			)
			
			print_success(f"Connected to MySQL server as {self.username}")
			
			# Store connection and credentials for the shell
			additional_data = {
				'host': self.host,
				'port': int(self.port),
				'username': self.username,
				'password': self.password,
				'database': self.database,
				'connection': connection  # Store connection object
			}
			
			# Return connection, target, port, and additional data
			return (connection, self.host, int(self.port), additional_data)
			
		except pymysql.Error as e:
			print_error(f"MySQL connection failed: {e}")
			return False
		except Exception as e:
			print_error(f"Error: {e}")
			return False

