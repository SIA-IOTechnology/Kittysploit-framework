from kittysploit import *
from lib.protocols.mssql.mssql_client import MSSQLClient


class Module(Post, MSSQLClient):

	__info__ = {
		"name": "Enumerate MSSQL Databases",
		"description": "Enumerate databases, schemas/tables, and columns on Microsoft SQL Server",
		"author": "KittySploit Team",
		"session_type": SessionType.MSSQL,
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
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	database = OptString("", "Specific database to enumerate (all user DBs if empty)", False)
	show_data = OptBool(False, "Show sample rows from tables (TOP 5)", False)
	include_system = OptBool(False, "Include system databases (master, msdb, model, tempdb)", False)

	def run(self):
		try:
			info = self.get_session_info()
			version = info.get("version") or self.get_version()
			if version:
				print_info(version.splitlines()[0] if "\n" in version else version)

			current_db = info.get("current_database", "")
			print_info("=" * 80)
			print_status("Server databases")
			databases = self.list_databases(include_system=bool(self.include_system))
			for db_name in databases:
				marker = " (current)" if db_name == current_db else ""
				print_info(f"  {db_name}{marker}")

			target_dbs = databases
			if self.database:
				target_dbs = [str(self.database).strip()]
				if target_dbs[0] not in databases and not self.include_system:
					print_warning(f"Database '{target_dbs[0]}' not in user database list")

			for db_name in target_dbs:
				print_info("-" * 80)
				print_status(f"Tables in database: {db_name}")
				try:
					self.use_database(db_name)
					tables = self.list_tables(db_name)
					if not tables:
						print_info("  (no tables)")
						continue

					for schema_name, table_name in tables:
						print_info(f"  - {schema_name}.{table_name}")
						for col in self.describe_table(table_name, schema_name, db_name):
							col_name = col.get("COLUMN_NAME", "")
							col_type = col.get("DATA_TYPE", "")
							nullable = col.get("IS_NULLABLE", "")
							max_len = col.get("CHARACTER_MAXIMUM_LENGTH")
							type_hint = col_type
							if max_len not in (None, ""):
								type_hint = f"{col_type}({max_len})"
							null_hint = " NULL" if nullable == "YES" else ""
							print_info(f"      {col_name} ({type_hint}){null_hint}")

						if self.show_data:
							try:
								quoted = f"[{schema_name}].[{table_name}]"
								sample = self.execute_query(
									f"SELECT TOP 5 * FROM {quoted}"
								)
								if sample:
									print_info(f"      Sample ({len(sample)} row(s)):")
									for i, row in enumerate(sample, 1):
										print_info(f"        [{i}] {row}")
							except Exception as exc:
								print_warning(f"      Could not read sample: {exc}")
				except Exception as exc:
					print_warning(f"Error accessing database {db_name}: {exc}")

			print_info("=" * 80)
			print_success("MSSQL enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating MSSQL databases: {exc}"
			)
