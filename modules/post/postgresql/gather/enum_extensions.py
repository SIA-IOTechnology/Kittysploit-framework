from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Extensions",
		"description": "List installed extensions and versions (pgcrypto, etc.)",
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	}

	database = OptString("", "Connect to database before listing (empty = current)", False)

	def run(self):
		try:
			version = self.get_version()
			if version:
				print_info(version)

			if self.database:
				conn = self.get_postgresql_connection()
				conn.autocommit = True
				with conn.cursor() as cur:
					cur.execute(
						"SELECT 1 FROM pg_database WHERE datname = %s;",
						(str(self.database),),
					)
					if not cur.fetchone():
						raise ProcedureError(
							FailureType.NotFound,
							f"Database not found: {self.database}",
						)

			rows = self.execute_query(
				"SELECT e.extname, e.extversion, n.nspname "
				"FROM pg_extension e "
				"JOIN pg_namespace n ON n.oid = e.extnamespace "
				"ORDER BY e.extname;"
			)
			if not rows:
				print_warning("No extensions installed in current database")
				return True

			print_success(f"Found {len(rows)} extension(s):")
			for extname, extversion, nspname in rows:
				print_info(f"  {extname} {extversion} (schema: {nspname})")
				if extname == "pgcrypto":
					for fn in (
						"pgp_pub_decrypt_bytea",
						"pgp_sym_decrypt_bytea",
						"pgp_pub_encrypt_bytea",
					):
						mark = "yes" if self.function_exists(fn) else "no"
						print_info(f"    {fn}: {mark}")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating extensions: {exc}"
			)
