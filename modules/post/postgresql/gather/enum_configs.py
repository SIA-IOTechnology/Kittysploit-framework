from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Configuration",
		"description": "Dump security-relevant server settings and paths",
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	},
	}

	SETTINGS = (
		"server_version",
		"data_directory",
		"config_file",
		"hba_file",
		"ident_file",
		"ssl",
		"ssl_cert_file",
		"ssl_key_file",
		"password_encryption",
		"log_connections",
		"log_disconnections",
		"log_statement",
		"log_line_prefix",
		"shared_preload_libraries",
		"listen_addresses",
		"port",
		"max_connections",
		"superuser_reserved_connections",
		"row_security",
	)

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Session")
			for key, value in info.items():
				print_info(f"  {key}: {value}")

			print_info("-" * 80)
			print_status("Server settings")
			settings = self.get_settings(list(self.SETTINGS))
			for name in self.SETTINGS:
				value = settings.get(name)
				if value is None:
					print_warning(f"  {name}: (unavailable)")
				else:
					print_info(f"  {name}: {value}")

			version = self.get_version()
			if version and not settings.get("server_version"):
				print_info(f"  version(): {version}")

			print_info("-" * 80)
			print_status("Installed extensions (current database)")
			rows = self.execute_query(
				"SELECT extname, extversion FROM pg_extension ORDER BY extname;"
			)
			for extname, extversion in rows or []:
				print_info(f"  {extname}: {extversion}")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating configuration: {exc}"
			)
