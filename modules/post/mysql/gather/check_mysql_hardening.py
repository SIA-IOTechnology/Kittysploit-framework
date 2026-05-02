from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient


class Module(Post, MySQLClient):

	__info__ = {
		"name": "Check MySQL Hardening",
		"description": "Audit common MySQL security hardening controls and risky configurations",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}

	include_system = OptBool(False, "Include system/internal accounts in account checks", False)
	verbose = OptBool(False, "Show extra diagnostic information", False)

	def run(self):
		try:
			current_user = self.get_current_user()
			if current_user:
				print_info(f"Current MySQL session user: {current_user}")

			version = self._get_mysql_version()
			if version:
				print_info(f"MySQL version: {version}")

			print_info("=" * 80)
			print_status("Running MySQL hardening audit")

			self._check_anonymous_accounts()
			self._check_remote_root()
			self._check_empty_or_weak_auth()
			self._check_password_policy()
			self._check_file_and_local_infile()
			self._check_ssl_and_network()

			print_info("=" * 80)
			print_success("Hardening audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error during MySQL hardening audit: {e}")

	def _get_mysql_version(self):
		try:
			row = self.execute_query("SELECT VERSION() AS version", fetch_all=False)
			return row.get("version") if row else None
		except Exception:
			return None

	def _query_count(self, query):
		try:
			row = self.execute_query(query, fetch_all=False)
			return int(row.get("count", 0)) if row else 0
		except Exception:
			return None

	def _query_variable(self, name):
		try:
			row = self.execute_query(f"SHOW VARIABLES LIKE '{name}'", fetch_all=False)
			if not row:
				return None
			return row.get("Value")
		except Exception:
			return None

	def _check_anonymous_accounts(self):
		print_info("-" * 80)
		print_status("Check: Anonymous accounts")

		count = self._query_count("SELECT COUNT(*) AS count FROM mysql.user WHERE User = ''")
		if count is None:
			print_warning("Cannot query mysql.user for anonymous account check")
			return

		if count > 0:
			print_error(f"Found {count} anonymous account(s) in mysql.user")
		else:
			print_success("No anonymous accounts found")

	def _check_remote_root(self):
		print_info("-" * 80)
		print_status("Check: Remote root access")

		query = (
			"SELECT User, Host FROM mysql.user "
			"WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
		)
		try:
			rows = self.execute_query(query)
		except Exception as e:
			print_warning(f"Cannot query root host restrictions: {e}")
			return

		if rows:
			print_error(f"Found {len(rows)} remote root account(s):")
			for row in rows:
				print_info(f"  'root'@'{row.get('Host', '')}'")
		else:
			print_success("No remote root accounts detected")

	def _check_empty_or_weak_auth(self):
		print_info("-" * 80)
		print_status("Check: Empty password / weak auth plugin")

		system_filter = ""
		if not self.include_system:
			system_filter = "AND User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'mysqlxsys')"

		empty_auth_query = (
			"SELECT User, Host, plugin, authentication_string "
			"FROM mysql.user "
			"WHERE (authentication_string IS NULL OR authentication_string = '') "
			f"{system_filter} "
			"ORDER BY User, Host"
		)
		try:
			rows = self.execute_query(empty_auth_query)
		except Exception as e:
			print_warning(f"Cannot check empty authentication_string: {e}")
			rows = []

		if rows:
			print_error(f"Found {len(rows)} account(s) with empty authentication_string:")
			for row in rows:
				print_info(f"  '{row.get('User', '')}'@'{row.get('Host', '')}' plugin={row.get('plugin', 'N/A')}")
		else:
			print_success("No account with empty authentication_string found")

		try:
			plugin_rows = self.execute_query(
				"SELECT User, Host, plugin FROM mysql.user "
				f"WHERE plugin IN ('mysql_old_password', 'mysql_native_password') {system_filter} "
				"ORDER BY User, Host"
			)
		except Exception as e:
			print_warning(f"Cannot audit authentication plugins: {e}")
			return

		if plugin_rows:
			print_warning(f"Found {len(plugin_rows)} account(s) using legacy/less-strong auth plugin(s):")
			for row in plugin_rows:
				print_info(f"  '{row.get('User', '')}'@'{row.get('Host', '')}' plugin={row.get('plugin', '')}")
		else:
			print_success("No legacy auth plugin usage detected")

	def _check_password_policy(self):
		print_info("-" * 80)
		print_status("Check: Password policy")

		validate_policy = self._query_variable("validate_password.policy")
		validate_length = self._query_variable("validate_password.length")
		reuse_history = self._query_variable("password_history")
		reuse_time = self._query_variable("password_reuse_interval")

		if validate_policy is None and validate_length is None:
			print_warning("validate_password plugin or variables not visible")
		else:
			if validate_policy:
				print_info(f"validate_password.policy: {validate_policy}")
			if validate_length:
				print_info(f"validate_password.length: {validate_length}")

		if reuse_history is not None:
			if str(reuse_history) == "0":
				print_warning("password_history is 0 (password reuse not restricted)")
			else:
				print_success(f"password_history: {reuse_history}")

		if reuse_time is not None:
			if str(reuse_time) == "0":
				print_warning("password_reuse_interval is 0 (no time-based reuse restriction)")
			else:
				print_success(f"password_reuse_interval: {reuse_time}")

		if self.verbose:
			default_auth = self._query_variable("default_authentication_plugin")
			if default_auth is not None:
				print_info(f"default_authentication_plugin: {default_auth}")

	def _check_file_and_local_infile(self):
		print_info("-" * 80)
		print_status("Check: FILE privilege and local_infile")

		try:
			file_priv = self.check_privilege("FILE")
			if file_priv:
				print_warning("Current account has FILE privilege")
			else:
				print_success("Current account does not have FILE privilege")
		except Exception as e:
			print_warning(f"Could not test FILE privilege: {e}")

		local_infile = self._query_variable("local_infile")
		if local_infile is None:
			print_warning("Could not read local_infile setting")
		elif str(local_infile).upper() in ("ON", "1", "TRUE"):
			print_warning(f"local_infile is enabled ({local_infile})")
		else:
			print_success(f"local_infile is disabled ({local_infile})")

		secure_file_priv = self.get_secure_file_priv()
		if secure_file_priv is None:
			print_warning("Could not read secure_file_priv")
		elif secure_file_priv == "":
			print_error("secure_file_priv is empty (broad file read/write surface)")
		else:
			print_success(f"secure_file_priv: {secure_file_priv}")

	def _check_ssl_and_network(self):
		print_info("-" * 80)
		print_status("Check: SSL and network exposure")

		require_secure_transport = self._query_variable("require_secure_transport")
		if require_secure_transport is None:
			print_warning("Could not read require_secure_transport")
		elif str(require_secure_transport).upper() in ("ON", "1", "TRUE"):
			print_success("require_secure_transport is enabled")
		else:
			print_warning("require_secure_transport is disabled")

		skip_networking = self._query_variable("skip_networking")
		bind_address = self._query_variable("bind_address")

		if skip_networking is not None:
			if str(skip_networking).upper() in ("ON", "1", "TRUE"):
				print_success("skip_networking is enabled (TCP disabled)")
			else:
				print_warning("skip_networking is disabled (TCP enabled)")

		if bind_address is not None:
			if bind_address in ("0.0.0.0", "::", "*"):
				print_warning(f"MySQL listens on all interfaces (bind_address={bind_address})")
			else:
				print_success(f"bind_address={bind_address}")
