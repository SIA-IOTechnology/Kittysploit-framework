from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Enumerate PostgreSQL Databases",
		"description": "Enumerate databases and tables/schemas in the current database",
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	    'chain': {
	        'consumes_capabilities': ['db_access'],
	        'suggested_followups': [
	            'post/postgresql/gather/enum_roles',
	            'post/postgresql/exploits/copy_program_exec',
	        ],
	    },
	},
	}

	schema = OptString("", "Limit to one schema (empty = all user schemas)", False)
	show_data = OptBool(False, "Show sample rows from tables (LIMIT 5)", False)

	def run(self):
		try:
			version = self.get_version()
			if version:
				print_info(version)

			info = self.get_session_info()
			current_db = info.get("current_database", "")
			print_info("=" * 80)
			print_status("Cluster databases")
			for db_name in self.list_databases():
				marker = " (current)" if db_name == current_db else ""
				print_info(f"  {db_name}{marker}")

			print_info("-" * 80)
			print_status(f"Schemas and tables in database: {current_db or '(unknown)'}")

			schemas = self.list_schemas()
			if self.schema:
				schemas = [s for s in schemas if s == str(self.schema)]

			for schema_name in schemas:
				print_info(f"\n  Schema: {schema_name}")
				tables = self.list_tables(schema_name)
				if not tables:
					print_info("    (no tables)")
					continue

				for table_name in tables:
					print_info(f"    - {schema_name}.{table_name}")
					for col in self.describe_table(table_name, schema_name):
						name, dtype, nullable, default = col[0], col[1], col[2], col[3]
						extra = " NULL" if nullable == "YES" else ""
						if default:
							extra += f" default={default}"
						print_info(f"        {name} ({dtype}){extra}")

					if self.show_data:
						try:
							quoted = f'"{schema_name}"."{table_name}"'
							sample = self.execute_query(
								f"SELECT * FROM {quoted} LIMIT 5;"
							)
							if sample:
								print_info(f"      Sample ({len(sample)} row(s)):")
								for i, row in enumerate(sample, 1):
									print_info(f"        [{i}] {row}")
						except Exception as exc:
							print_warning(f"      Could not read sample: {exc}")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating databases: {exc}"
			)
