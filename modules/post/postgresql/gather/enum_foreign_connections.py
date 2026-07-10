from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Foreign Connections",
		"description": (
			"List postgres_fdw servers, user mappings, foreign tables, "
			"dblink sessions, and connection strings in function source"
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
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	search_source = OptBool(True, "Search function bodies for host/user/password strings", False)

	def run(self):
		try:
			print_info("=" * 80)
			self._enum_postgres_fdw()
			self._enum_foreign_tables()
			self._enum_dblink()
			if self.search_source:
				self._search_connection_strings()

			print_info("=" * 80)
			print_success("Foreign connection enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Foreign connection enumeration failed: {exc}"
			)

	def _enum_postgres_fdw(self):
		print_status("postgres_fdw servers")
		if not self.extension_installed("postgres_fdw"):
			print_info("  postgres_fdw not installed in current database")
			return

		try:
			servers = self.execute_query(
				"SELECT s.srvname, w.fdwname, s.srvoptions, s.srvowner::regrole::text "
				"FROM pg_foreign_server s "
				"JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw "
				"ORDER BY s.srvname;"
			)
		except Exception as exc:
			print_warning(f"  Cannot read foreign servers: {exc}")
			return

		if not servers:
			print_info("  No foreign servers defined")
			return

		print_success(f"  Found {len(servers)} foreign server(s):")
		for srvname, fdwname, srvoptions, owner in servers:
			opts = self._format_options(srvoptions)
			print_info(f"    {srvname} (fdw={fdwname}, owner={owner})")
			if opts:
				print_info(f"      {opts}")

		try:
			mappings = self.execute_query(
				"SELECT COALESCE(r.rolname, 'PUBLIC') AS local_role, "
				"s.srvname, u.umoptions "
				"FROM pg_user_mapping u "
				"JOIN pg_foreign_server s ON s.oid = u.umserver "
				"LEFT JOIN pg_roles r ON r.oid = u.umuser "
				"ORDER BY s.srvname, local_role;"
			)
		except Exception as exc:
			print_warning(f"  Cannot read user mappings: {exc}")
			return

		if mappings:
			print_info("  User mappings:")
			for local_role, srvname, umoptions in mappings:
				opts = self._format_options(umoptions)
				print_info(f"    {local_role} -> {srvname}: {opts or '(no options)'}")

	def _enum_foreign_tables(self):
		print_info("-" * 80)
		print_status("Foreign tables")
		try:
			rows = self.execute_query(
				"SELECT n.nspname, c.relname, s.srvname, "
				"pg_get_userbyid(c.relowner) AS owner "
				"FROM pg_class c "
				"JOIN pg_namespace n ON n.oid = c.relnamespace "
				"JOIN pg_foreign_table ft ON ft.ftrelid = c.oid "
				"JOIN pg_foreign_server s ON s.oid = ft.ftserver "
				"ORDER BY n.nspname, c.relname "
				"LIMIT 50;"
			)
		except Exception as exc:
			print_warning(f"  Cannot list foreign tables: {exc}")
			return

		if not rows:
			print_info("  No foreign tables in current database")
			return

		print_success(f"  Found {len(rows)} foreign table(s):")
		for schema, table, srvname, owner in rows:
			print_info(f"    {schema}.{table} -> server {srvname} (owner={owner})")

	def _enum_dblink(self):
		print_info("-" * 80)
		print_status("dblink")
		if not self.extension_installed("dblink"):
			print_info("  dblink not installed in current database")
			return

		if not self.function_exists("dblink_get_connections"):
			print_warning("  dblink_get_connections() not available")
			return

		try:
			rows = self.execute_query("SELECT dblink_get_connections();", fetch_all=False)
			conns = rows[0] if rows else None
		except Exception as exc:
			print_warning(f"  dblink_get_connections failed: {exc}")
			return

		if not conns:
			print_info("  No active dblink connections")
			return

		print_success(f"  Active dblink connection(s): {conns}")

	def _search_connection_strings(self):
		print_info("-" * 80)
		print_status("Connection strings in function/trigger source")
		try:
			rows = self.execute_query(
				"SELECT n.nspname, p.proname, "
				"LEFT(p.prosrc, 300) AS src_preview "
				"FROM pg_proc p "
				"JOIN pg_namespace n ON n.oid = p.pronamespace "
				"WHERE p.prosrc IS NOT NULL "
				"AND ("
				"  p.prosrc ILIKE '%dblink%' "
				"  OR p.prosrc ILIKE '%host=%' "
				"  OR p.prosrc ILIKE '%password=%' "
				"  OR p.prosrc ILIKE '%postgres_fdw%' "
				"  OR p.prosrc ILIKE '%dbname=%' "
				") "
				"AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' "
				"ORDER BY n.nspname, p.proname "
				"LIMIT 30;"
			)
		except Exception as exc:
			print_warning(f"  Source search failed: {exc}")
			return

		if not rows:
			print_info("  No matching function source found")
			return

		print_warning(f"  Found {len(rows)} function(s) with connection hints:")
		for schema, name, preview in rows:
			snippet = (preview or "").replace("\n", " ").strip()
			if len(snippet) > 160:
				snippet = snippet[:157] + "..."
			print_info(f"    {schema}.{name}(): {snippet}")

	@staticmethod
	def _format_options(options) -> str:
		if not options:
			return ""
		if isinstance(options, (list, tuple)):
			return ", ".join(str(o) for o in options)
		return str(options)
