from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Roles",
		"description": "Enumerate roles, login capability, and privilege flags",
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	    'cost': 1.5,
	    'noise': 0.5,
	    'value': 1.0,
	    'requires': 	    {'min_endpoints': 0,
	     'min_params': 0,
	     'tech_hints_any': [],
	     'tech_hints_all': [],
	     'specializations_any': [],
	     'risk_signals_any': [],
	     'auth_session': False,
	     'capabilities_any': [],
	     'capabilities_all': [],
	     'confidence_min': {},
	     'confidence_min_any': {},
	     'endpoint_pattern_any': [],
	     'param_any': [],
	     'api_surface_ready': False},
	    'chain': 	    {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 's7comm', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	include_system = OptBool(False, "Include pg_* and built-in roles", False)
	verbose = OptBool(False, "Show role membership (pg_auth_members)", False)

	def run(self):
		try:
			info = self.get_session_info()
			if info:
				print_info("Session context:")
				for key, value in info.items():
					print_info(f"  {key}: {value}")

			print_info("=" * 80)
			rows = self.list_roles(include_system=bool(self.include_system))
			if not rows:
				print_warning("No roles returned (insufficient privileges?)")
				return False

			print_success(f"Found {len(rows)} role(s):")
			for row in rows:
				(
					rolname,
					superuser,
					createdb,
					createrole,
					replication,
					bypassrls,
					canlogin,
					validuntil,
				) = row
				flags = []
				if superuser:
					flags.append("SUPERUSER")
				if createdb:
					flags.append("CREATEDB")
				if createrole:
					flags.append("CREATEROLE")
				if replication:
					flags.append("REPLICATION")
				if bypassrls:
					flags.append("BYPASSRLS")
				if canlogin:
					flags.append("LOGIN")
				flag_str = ", ".join(flags) if flags else "none"
				print_info(f"  {rolname} [{flag_str}] valid_until={validuntil or 'never'}")

			if self.verbose:
				print_info("-" * 80)
				print_status("Role membership:")
				try:
					members = self.execute_query(
						"SELECT r.rolname AS role, m.rolname AS member "
						"FROM pg_auth_members am "
						"JOIN pg_roles r ON r.oid = am.roleid "
						"JOIN pg_roles m ON m.oid = am.member "
						"ORDER BY r.rolname, m.rolname;"
					)
					for role, member in members:
						print_info(f"  {member} -> {role}")
				except Exception as exc:
					print_warning(f"Could not read pg_auth_members: {exc}")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating roles: {exc}"
			)
