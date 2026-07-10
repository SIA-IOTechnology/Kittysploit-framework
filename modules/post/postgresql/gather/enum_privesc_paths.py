from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Privilege Escalation Paths",
		"description": (
			"Find likely PostgreSQL privilege escalation paths: superuser role chain, "
			"SECURITY DEFINER functions, unsafe search_path, and risky extensions"
		),
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
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Session")
			for key, value in info.items():
				print_info(f"  {key}: {value}")

			self._check_superuser_chain()
			self._check_security_definer_functions()
			self._check_unsafe_search_path()
			self._check_risky_extensions()
			self._check_table_ownership()

			print_info("=" * 80)
			print_success("Privilege escalation path audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Privesc enumeration failed: {exc}"
			)

	def _check_superuser_chain(self):
		print_info("-" * 80)
		print_status("Superuser roles and membership chain")
		try:
			rows = self.execute_query(
				"SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname;"
			)
			if rows:
				print_warning(f"Superuser role(s): {', '.join(r[0] for r in rows)}")
			else:
				print_info("No superuser roles visible")
		except Exception as exc:
			print_warning(f"Cannot list superusers: {exc}")

		try:
			rows = self.execute_query(
				"SELECT m.rolname AS member, r.rolname AS inherits "
				"FROM pg_auth_members am "
				"JOIN pg_roles r ON r.oid = am.roleid "
				"JOIN pg_roles m ON m.oid = am.member "
				"WHERE r.rolsuper OR r.rolcreaterole "
				"ORDER BY r.rolname, m.rolname;"
			)
			if rows:
				print_info("Memberships leading to powerful roles:")
				for member, role in rows:
					print_info(f"  {member} -> {role}")
			else:
				print_info("No memberships to superuser/createrole roles found")
		except Exception as exc:
			print_warning(f"Cannot read role memberships: {exc}")

	def _check_security_definer_functions(self):
		print_info("-" * 80)
		print_status("SECURITY DEFINER functions (executable by current user)")
		try:
			rows = self.execute_query(
				"SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner, "
				"p.prosecdef, p.proconfig "
				"FROM pg_proc p "
				"JOIN pg_namespace n ON n.oid = p.pronamespace "
				"WHERE p.prosecdef "
				"AND has_function_privilege(p.oid, 'EXECUTE') "
				"AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' "
				"ORDER BY n.nspname, p.proname "
				"LIMIT 50;"
			)
		except Exception as exc:
			print_warning(f"Cannot query SECURITY DEFINER functions: {exc}")
			return

		if not rows:
			print_success("No executable SECURITY DEFINER functions in user schemas")
			return

		print_warning(f"Found {len(rows)} executable SECURITY DEFINER function(s):")
		for schema, name, owner, secdef, config in rows:
			cfg = ", ".join(config) if config else "default search_path"
			print_info(f"  {schema}.{name}() owner={owner} config=[{cfg}]")

	def _check_unsafe_search_path(self):
		print_info("-" * 80)
		print_status("SECURITY DEFINER with writable search_path")
		try:
			rows = self.execute_query(
				"SELECT n.nspname, p.proname, p.proconfig "
				"FROM pg_proc p "
				"JOIN pg_namespace n ON n.oid = p.pronamespace "
				"WHERE p.prosecdef "
				"AND p.proconfig IS NOT NULL "
				"AND EXISTS ("
				"  SELECT 1 FROM unnest(p.proconfig) c "
				"  WHERE c LIKE 'search_path=%public%' OR c = 'search_path=public'"
				") "
				"ORDER BY n.nspname, p.proname "
				"LIMIT 30;"
			)
		except Exception as exc:
			print_warning(f"Cannot audit search_path: {exc}")
			return

		if rows:
			print_warning("Functions with potentially unsafe search_path:")
			for schema, name, config in rows:
				print_info(f"  {schema}.{name}() {config}")
		else:
			print_success("No obvious public search_path on SECURITY DEFINER functions")

	def _check_risky_extensions(self):
		print_info("-" * 80)
		print_status("Risky extensions for lateral movement / code execution")
		risky = {
			"dblink": "SQL queries to remote databases",
			"postgres_fdw": "Foreign data wrapper (credential exposure)",
			"file_fdw": "Read server files via foreign table",
			"plpython3u": "Untrusted Python in-database",
			"plpythonu": "Untrusted Python (legacy)",
			"plperlu": "Untrusted Perl in-database",
			"pljava": "Java in-database",
			"pg_cron": "Scheduled SQL jobs",
		}
		try:
			rows = self.execute_query(
				"SELECT extname FROM pg_extension WHERE extname = ANY(%s);",
				(list(risky.keys()),),
			)
		except Exception as exc:
			print_warning(f"Cannot query extensions: {exc}")
			return

		if not rows:
			print_success("No high-risk extensions in current database")
			return

		for (extname,) in rows:
			print_warning(f"  {extname}: {risky.get(extname, 'review manually')}")

	def _check_table_ownership(self):
		print_info("-" * 80)
		print_status("Tables owned by superuser roles (writable by you?)")
		try:
			rows = self.execute_query(
				"SELECT c.relnamespace::regnamespace::text AS schema, "
				"c.relname AS table, pg_get_userbyid(c.relowner) AS owner, "
				"has_table_privilege(c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE') AS writable "
				"FROM pg_class c "
				"JOIN pg_roles r ON r.oid = c.relowner "
				"WHERE c.relkind IN ('r', 'p') "
				"AND r.rolsuper "
				"AND has_table_privilege(c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE') "
				"ORDER BY schema, table "
				"LIMIT 30;"
			)
		except Exception as exc:
			print_warning(f"Cannot audit table ownership: {exc}")
			return

		if rows:
			print_warning(f"You can modify {len(rows)} table(s) owned by a superuser:")
			for schema, table, owner, writable in rows:
				print_info(f"  {schema}.{table} owner={owner} writable={writable}")
		else:
			print_info("No writable superuser-owned tables found")
