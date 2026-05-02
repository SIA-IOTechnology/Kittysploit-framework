from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient


class Module(Post, MySQLClient):

	__info__ = {
		"name": "Enumerate MySQL Roles",
		"description": "Enumerate MySQL roles and role assignments to users",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}

	include_system = OptBool(False, "Include system/internal accounts when possible", False)
	verbose = OptBool(False, "Show extra role details and grants", False)

	def run(self):
		try:
			current_user = self.get_current_user()
			if current_user:
				print_info(f"Current MySQL session user: {current_user}")

			version = self._get_mysql_version()
			if version:
				print_info(f"MySQL version: {version}")

			print_info("=" * 80)
			found_any = self._enum_roles_from_mysql_tables()
			if not found_any:
				print_warning("Primary role mapping tables are not accessible. Trying information_schema fallback.")
				found_any = self._enum_roles_from_information_schema()

			if not found_any:
				print_warning("No role mapping found. Showing enabled roles for current session.")
				return self._enum_enabled_roles()

			return True
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error enumerating MySQL roles: {e}")

	def _get_mysql_version(self):
		try:
			row = self.execute_query("SELECT VERSION() AS version", fetch_all=False)
			return row.get("version") if row else None
		except Exception:
			return None

	def _enum_roles_from_mysql_tables(self):
		"""
		Primary method for MySQL 8+:
		- mysql.user where is_role='Y'
		- mysql.role_edges for role-to-user assignments
		Returns True if at least one role or mapping was found.
		"""
		roles = self._get_roles_from_mysql_user()
		mappings = self._get_role_edges()

		if not roles and not mappings:
			return False

		if roles:
			print_success(f"Found {len(roles)} role account(s):")
			for role_user, role_host in roles:
				account = f"'{role_user}'@'{role_host}'"
				print_info(f"  {account}")
				if self.verbose:
					self._print_grants_for_account(role_user, role_host)
		else:
			print_warning("No role rows discovered in mysql.user")

		if mappings:
			print_info("-" * 80)
			print_success(f"Found {len(mappings)} role assignment(s):")
			for role_user, role_host, to_user, to_host in mappings:
				role_acc = f"'{role_user}'@'{role_host}'"
				user_acc = f"'{to_user}'@'{to_host}'"
				print_info(f"  {role_acc} -> {user_acc}")
		else:
			print_warning("No role assignments discovered in mysql.role_edges")

		return True

	def _enum_roles_from_information_schema(self):
		"""
		Fallback method:
		Extract role-like grants from information_schema.enabled_roles /
		information_schema.applicable_roles for current session visibility.
		Returns True if rows found.
		"""
		found = False

		for query, label in (
			("SELECT ROLE_NAME, ROLE_HOST, IS_DEFAULT FROM information_schema.applicable_roles ORDER BY ROLE_NAME, ROLE_HOST", "Applicable roles"),
			("SELECT ROLE_NAME, ROLE_HOST FROM information_schema.enabled_roles ORDER BY ROLE_NAME, ROLE_HOST", "Enabled roles"),
		):
			try:
				rows = self.execute_query(query)
			except Exception as e:
				print_warning(f"{label} query failed: {e}")
				continue

			if not rows:
				continue

			found = True
			print_success(f"{label}:")
			for row in rows:
				role_name = row.get("ROLE_NAME", "")
				role_host = row.get("ROLE_HOST", "%")
				is_default = row.get("IS_DEFAULT")

				line = f"  '{role_name}'@'{role_host}'"
				if is_default is not None:
					line += f" | default={is_default}"
				print_info(line)

		return found

	def _enum_enabled_roles(self):
		try:
			rows = self.execute_query("SELECT CURRENT_ROLE() AS current_role", fetch_all=False)
			if not rows:
				print_warning("CURRENT_ROLE() returned no data")
				return True

			print_success("Current enabled role context:")
			print_info(f"  {rows.get('current_role', 'NONE')}")
			return True
		except Exception as e:
			print_error(f"Failed to query CURRENT_ROLE(): {e}")
			return False

	def _get_roles_from_mysql_user(self):
		where_filters = ["is_role = 'Y'"]
		if not self.include_system:
			where_filters.append("User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'mysqlxsys')")

		query = (
			"SELECT User, Host "
			"FROM mysql.user "
			f"WHERE {' AND '.join(where_filters)} "
			"ORDER BY User, Host"
		)

		try:
			rows = self.execute_query(query)
		except Exception as e:
			print_warning(f"mysql.user role query failed: {e}")
			return []

		roles = []
		for row in rows:
			user = row.get("User", "")
			host = row.get("Host", "")
			if user:
				roles.append((user, host))
		return roles

	def _get_role_edges(self):
		query = (
			"SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST "
			"FROM mysql.role_edges "
			"ORDER BY FROM_USER, FROM_HOST, TO_USER, TO_HOST"
		)
		try:
			rows = self.execute_query(query)
		except Exception as e:
			print_warning(f"mysql.role_edges query failed: {e}")
			return []

		mappings = []
		for row in rows:
			from_user = row.get("FROM_USER", "")
			from_host = row.get("FROM_HOST", "")
			to_user = row.get("TO_USER", "")
			to_host = row.get("TO_HOST", "")

			if not self.include_system and (
				from_user in ("mysql.sys", "mysql.session", "mysql.infoschema", "mysqlxsys")
				or to_user in ("mysql.sys", "mysql.session", "mysql.infoschema", "mysqlxsys")
			):
				continue

			mappings.append((from_user, from_host, to_user, to_host))
		return mappings

	def _print_grants_for_account(self, username, host):
		escaped_user = username.replace("`", "``").replace("\\", "\\\\").replace("'", "\\'")
		escaped_host = host.replace("`", "``").replace("\\", "\\\\").replace("'", "\\'")
		query = f"SHOW GRANTS FOR '{escaped_user}'@'{escaped_host}'"

		try:
			rows = self.execute_query(query)
			if not rows:
				print_info("    Grants: none visible")
				return
			print_info("    Grants:")
			for row in rows:
				print_info(f"      - {list(row.values())[0]}")
		except Exception:
			print_warning(f"    Could not read grants for '{username}'@'{host}'")
