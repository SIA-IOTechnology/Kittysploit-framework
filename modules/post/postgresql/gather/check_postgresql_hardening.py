from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Check PostgreSQL Hardening",
		"description": "Audit common PostgreSQL security misconfigurations",
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
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	def run(self):
		try:
			print_status("PostgreSQL hardening audit")
			if self.get_version():
				print_info(self.get_version())

			print_info("=" * 80)
			self._check_superuser_session()
			self._check_superuser_roles()
			self._check_bypass_rls_roles()
			self._check_trust_and_ssl()
			self._check_logging()
			self._check_extensions()

			print_info("=" * 80)
			print_success("Hardening audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Hardening audit failed: {exc}"
			)

	def _check_superuser_session(self):
		print_info("-" * 80)
		print_status("Check: Current session is superuser")
		if self.is_superuser():
			print_warning("Current session has superuser privileges")
		else:
			print_success("Current session is not superuser")

	def _check_superuser_roles(self):
		print_info("-" * 80)
		print_status("Check: Superuser roles")
		try:
			rows = self.execute_query(
				"SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY rolname;"
			)
		except Exception as exc:
			print_warning(f"Cannot list superuser roles: {exc}")
			return
		if len(rows) > 1:
			print_warning(f"Found {len(rows)} superuser role(s):")
		for (rolname,) in rows:
			print_info(f"  {rolname}")

	def _check_bypass_rls_roles(self):
		print_info("-" * 80)
		print_status("Check: BYPASSRLS roles")
		try:
			rows = self.execute_query(
				"SELECT rolname FROM pg_roles WHERE rolbypassrls ORDER BY rolname;"
			)
		except Exception as exc:
			print_warning(f"Cannot list BYPASSRLS roles: {exc}")
			return
		if rows:
			print_warning(f"Found {len(rows)} role(s) with BYPASSRLS:")
			for (rolname,) in rows:
				print_info(f"  {rolname}")
		else:
			print_success("No BYPASSRLS roles")

	def _check_trust_and_ssl(self):
		print_info("-" * 80)
		print_status("Check: SSL and listen addresses")
		ssl = self.get_setting("ssl")
		if ssl and str(ssl).lower() in ("on", "true", "1"):
			print_success(f"ssl is enabled ({ssl})")
		else:
			print_warning(f"ssl is disabled or off ({ssl})")

		listen = self.get_setting("listen_addresses")
		if listen and listen.strip() in ("*", "0.0.0.0", "::"):
			print_warning(f"listen_addresses exposes all interfaces: {listen}")
		elif listen:
			print_info(f"listen_addresses: {listen}")

		password_enc = self.get_setting("password_encryption")
		if password_enc:
			if str(password_enc) in ("md5", "password"):
				print_warning(f"password_encryption: {password_enc} (legacy)")
			else:
				print_success(f"password_encryption: {password_enc}")

	def _check_logging(self):
		print_info("-" * 80)
		print_status("Check: Logging")
		for setting in ("log_connections", "log_disconnections", "log_statement"):
			value = self.get_setting(setting)
			if value is None:
				print_warning(f"  {setting}: unavailable")
			elif str(value).lower() in ("on", "ddl", "all", "mod"):
				print_success(f"  {setting}: {value}")
			else:
				print_warning(f"  {setting}: {value}")

	def _check_extensions(self):
		print_info("-" * 80)
		print_status("Check: Risky extensions")
		risky = ("pgcrypto", "plpython3u", "plpythonu", "plperlu", "dblink", "file_fdw")
		try:
			rows = self.execute_query(
				"SELECT extname FROM pg_extension WHERE extname = ANY(%s);",
				(list(risky),),
			)
		except Exception as exc:
			print_warning(f"Cannot query extensions: {exc}")
			return
		if rows:
			print_warning("Potentially sensitive extensions installed:")
			for (extname,) in rows:
				print_info(f"  {extname}")
		else:
			print_success("No flagged extensions in current database")
