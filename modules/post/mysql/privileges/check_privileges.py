from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient

class Module(Post, MySQLClient):

	__info__ = {
		"name": "Check MySQL User Privileges",
		"description": "Check current MySQL user privileges and capabilities",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}	

	def run(self):
		try:
			user = self.get_current_user()
			if user:
				print_info(f"Current User: {user}")
			
			grants = self.execute_query("SHOW GRANTS")
			print_info("Grants:")
			for grant in grants:
				print_info(f"  {list(grant.values())[0]}")
			
			privileges_to_check = [
				'FILE', 'SUPER', 'PROCESS', 'RELOAD', 'SHUTDOWN',
				'CREATE USER', 'GRANT OPTION', 'REPLICATION SLAVE',
				'REPLICATION CLIENT', 'CREATE ROUTINE', 'ALTER ROUTINE',
				'CREATE TABLESPACE', 'CREATE VIEW', 'SHOW VIEW',
				'TRIGGER', 'EVENT', 'CREATE', 'DROP', 'INSERT',
				'UPDATE', 'DELETE', 'SELECT', 'ALTER'
			]
			
			print_info("Detailed Privileges:")
			for priv in privileges_to_check:
				has_priv = self.check_privilege(priv)
				if has_priv:
					print_success(f"{priv} is granted")
				else:
					print_error(f"{priv} is not granted")
			
			secure_file_priv = self.get_secure_file_priv()
			if secure_file_priv == '' or secure_file_priv is None:
				print_success("File operations possible (secure_file_priv is empty)")
			print_info(f"secure_file_priv: {secure_file_priv}")
			plugin_dir = self.get_plugin_dir()
			print_info(f"Plugin Directory: {plugin_dir}")
			return True
			
		except Exception as e:
			print_error(f"Error checking privileges: {e}")
			return False
