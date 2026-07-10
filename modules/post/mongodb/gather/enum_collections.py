from kittysploit import *
from lib.protocols.mongodb.mongodb_client import MongoDBClient


class Module(Post, MongoDBClient):

	__info__ = {
		"name": "Enumerate MongoDB Collections",
		"description": "Enumerate MongoDB databases, collections, and optional document samples",
		"author": "KittySploit Team",
		"session_type": SessionType.MONGODB,
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
	                               {'capability': 'ot_assets', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	database = OptString("", "Limit to one database (empty = all)", False)
	collection_filter = OptString("", "Filter collections by substring", False)
	show_stats = OptBool(True, "Show collection document counts", False)
	show_data = OptBool(False, "Show sample documents (limit 5 per collection)", False)
	skip_empty = OptBool(True, "Skip collections with zero documents when stats are available", False)

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("MongoDB session")
			for key in ("host", "port", "database", "version"):
				if info.get(key):
					print_info(f"  {key}: {info[key]}")

			databases = self.list_databases()
			if self.database:
				databases = [db for db in databases if db == str(self.database).strip()]

			name_filter = str(self.collection_filter or "").strip().lower()
			print_info("-" * 80)
			print_status(f"Databases ({len(databases)})")

			for db_name in databases:
				print_info(f"\n  Database: {db_name}")
				collections = self.list_collections(db_name)
				if name_filter:
					collections = [c for c in collections if name_filter in c.lower()]
				if not collections:
					print_info("    (no collections)")
					continue

				for coll_name in collections:
					stats = {}
					if self.show_stats or self.skip_empty:
						try:
							stats = self.collection_stats(db_name, coll_name)
						except ProcedureError:
							stats = {}
					count = stats.get("count")
					if self.skip_empty and count == 0:
						continue

					line = f"    - {coll_name}"
					if count is not None:
						line += f" ({count} document(s))"
					print_info(line)
					if stats.get("size") is not None:
						print_info(
							f"        size={stats.get('size')} bytes, "
							f"storageSize={stats.get('storageSize', 'n/a')}"
						)

					if self.show_data:
						try:
							docs = self.sample_documents(db_name, coll_name, limit=5)
							if docs:
								for i, doc in enumerate(docs, 1):
									print_info(f"        [{i}] {doc}")
							else:
								print_info("        (empty collection)")
						except Exception as exc:
							print_warning(f"        Could not sample documents: {exc}")

			print_info("=" * 80)
			print_success("MongoDB collection enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating MongoDB collections: {exc}"
			)
