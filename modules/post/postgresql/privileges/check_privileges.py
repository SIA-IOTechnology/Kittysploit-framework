from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Check PostgreSQL Privileges",
		"description": "Review current role capabilities and notable grants",
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

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			for key, value in info.items():
				print_info(f"  {key}: {value}")

			print_info("-" * 80)
			print_status("Role attributes (pg_roles)")
			try:
				rows = self.execute_query(
					"SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, "
					"rolreplication, rolbypassrls, rolcanlogin "
					"FROM pg_roles WHERE rolname = current_user;"
				)
				for row in rows:
					print_info(f"  {row}")
			except Exception as exc:
				print_warning(f"pg_roles query failed: {exc}")

			print_info("-" * 80)
			print_status("Database-level privileges")
			try:
				rows = self.execute_query(
					"SELECT datname, "
					"has_database_privilege(current_user, datname, 'CREATE') AS can_create, "
					"has_database_privilege(current_user, datname, 'CONNECT') AS can_connect "
					"FROM pg_database WHERE datistemplate = false ORDER BY datname;"
				)
				for datname, can_create, can_connect in rows:
					perms = []
					if can_connect:
						perms.append("CONNECT")
					if can_create:
						perms.append("CREATE")
					print_info(f"  {datname}: {', '.join(perms) or 'none'}")
			except Exception as exc:
				print_warning(f"Database privilege check failed: {exc}")

			print_info("-" * 80)
			print_status("Post-exploitation surface")
			if self.is_superuser():
				print_success("SUPERUSER — COPY FROM PROGRAM, pg_read_file, role changes")
			else:
				print_error("Not superuser — OS command/file primitives unavailable")

			if self.extension_installed("pgcrypto"):
				print_warning("pgcrypto is installed (crypto attack surface)")
			else:
				print_info("pgcrypto not installed in current database")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Privilege check failed: {exc}"
			)
