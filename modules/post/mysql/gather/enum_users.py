from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient


class Module(Post, MySQLClient):

	__info__ = {
		"name": "Enumerate MySQL Users",
		"description": "Enumerate MySQL users, hosts, password status, and privileges",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}

	include_system = OptBool(False, "Include system/internal accounts when possible", False)
	verbose = OptBool(False, "Display additional metadata and privileges", False)

	def run(self):
		try:
			current_user = self.get_current_user()
			if current_user:
				print_info(f"Current MySQL session user: {current_user}")

			print_info("=" * 80)
			print_status("Enumerating MySQL users from mysql.user")

			found_any = self._enum_from_mysql_user()
			if not found_any:
				print_warning("Unable to read mysql.user table. Trying alternative sources.")
				found_any = self._enum_from_information_schema()

			if not found_any:
				print_warning("Alternative sources unavailable. Falling back to visible grant information.")
				return self._enum_from_show_grants()

			return True

		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error enumerating MySQL users: {e}")

	def _enum_from_mysql_user(self):
		"""
		Enumerate users from mysql.user when the table is accessible.
		Returns True if accounts were identified.
		"""
		where_clause = ""
		if not self.include_system:
			where_clause = (
				"WHERE User NOT IN ('mysql.sys', 'mysql.session', "
				"'mysql.infoschema', 'mysqlxsys')"
			)

		query = (
			"SELECT User, Host, account_locked, password_expired, "
			"plugin FROM mysql.user "
			f"{where_clause} "
			"ORDER BY User, Host"
		)

		try:
			rows = self.execute_query(query)
		except Exception as e:
			print_warning(f"mysql.user query failed: {e}")
			return False

		if not rows:
			print_warning("No user rows returned from mysql.user")
			return False

		print_success(f"Found {len(rows)} MySQL account(s) in mysql.user:")
		for row in rows:
			username = row.get("User", "")
			host = row.get("Host", "")
			plugin = row.get("plugin", "unknown")
			locked = row.get("account_locked", "N/A")
			expired = row.get("password_expired", "N/A")
			self._print_account(username, host, plugin, locked, expired)
			if self.verbose:
				self._print_user_grants(username, host)

		return True

	def _enum_from_information_schema(self):
		"""
		Enumerate users through information_schema views when mysql.user is blocked.
		Returns True if accounts were identified.
		"""
		query = (
			"SELECT DISTINCT "
			"REPLACE(REPLACE(GRANTEE, \"'\", \"\"), '`', '') AS grantee "
			"FROM information_schema.user_privileges "
			"ORDER BY grantee"
		)
		try:
			rows = self.execute_query(query)
		except Exception as e:
			print_warning(f"information_schema.user_privileges query failed: {e}")
			return False

		if not rows:
			print_warning("No rows returned from information_schema.user_privileges")
			return False

		accounts = []
		for row in rows:
			grantee = row.get("grantee", "")
			if "@" not in grantee:
				continue
			username, host = grantee.split("@", 1)
			if not self.include_system and username in ("mysql.sys", "mysql.session", "mysql.infoschema", "mysqlxsys"):
				continue
			accounts.append((username, host))

		if not accounts:
			print_warning("No usable account entries found in information_schema.user_privileges")
			return False

		print_success(f"Found {len(accounts)} MySQL account(s) in information_schema.user_privileges:")
		for username, host in accounts:
			self._print_account(username, host)
			if self.verbose:
				self._print_user_grants(username, host)
		return True

	def _enum_from_show_grants(self):
		"""
		Fallback when mysql.user is not accessible: list grants for current user.
		Returns True if query runs, False otherwise.
		"""
		try:
			grants = self.execute_query("SHOW GRANTS")
			if not grants:
				print_warning("SHOW GRANTS returned no rows")
				return True

			print_success("Visible grants for current session account:")
			current_user = self.get_current_user()
			if current_user:
				print_info(f"  Account: {current_user}")
			for grant in grants:
				print_info(f"  {list(grant.values())[0]}")
			return True
		except Exception as e:
			print_error(f"SHOW GRANTS failed: {e}")
			return False

	def _print_account(self, username, host, plugin=None, locked=None, expired=None):
		account = f"'{username}'@'{host}'"
		if self.verbose:
			print_info(
				f"  {account} | plugin={plugin or 'N/A'} | "
				f"locked={locked if locked is not None else 'N/A'} | "
				f"password_expired={expired if expired is not None else 'N/A'}"
			)
		else:
			print_info(f"  {account}")

	def _print_user_grants(self, username, host):
		"""Print grants for a specific account when SHOW GRANTS is allowed."""
		escaped_user = username.replace("`", "``").replace("\\", "\\\\").replace("'", "\\'")
		escaped_host = host.replace("`", "``").replace("\\", "\\\\").replace("'", "\\'")
		query = f"SHOW GRANTS FOR '{escaped_user}'@'{escaped_host}'"

		try:
			grants = self.execute_query(query)
			if not grants:
				print_info("    Grants: none visible")
				return

			print_info("    Grants:")
			for grant in grants:
				print_info(f"      - {list(grant.values())[0]}")
		except Exception:
			print_warning(f"    Could not read grants for '{username}'@'{host}'")
