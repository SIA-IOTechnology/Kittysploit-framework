from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Flush Database",
		"description": "Delete all keys in the current database (FLUSHDB) or all databases (FLUSHALL)",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'destructive',
	    'effects': ['target_modification'],
	    'expected_requests': 1,
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
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': ['shell'],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	scope = OptString("db", "Scope: db (FLUSHDB) or all (FLUSHALL)", False)
	db = OptInteger(-1, "Database index before FLUSHDB (0-15, -1 = keep current)", False)
	confirm = OptBool(False, "Skip confirmation prompt", False)

	def run(self):
		try:
			scope = str(self.scope or "db").strip().lower()
			if scope not in ("db", "all"):
				raise ProcedureError(
					FailureType.ConfigurationError,
					"scope must be db or all",
				)

			if scope == "db" and self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			host = info.get("host", "localhost")
			port = info.get("port", 6379)
			current_db = info.get("db", 0)

			if scope == "all":
				print_warning(f"FLUSHALL will delete every key on {host}:{port}")
			else:
				key_count = self.count_keys()
				print_warning(
					f"FLUSHDB will delete {key_count} key(s) in db{current_db} on {host}:{port}"
				)

			if not self.confirm:
				response = input("Continue? (yes/no): ").strip().lower()
				if response not in ("yes", "y"):
					print_info("Flush cancelled")
					return False

			if scope == "all":
				self.flush_all()
				print_success("FLUSHALL completed")
			else:
				self.flush_db()
				print_success(f"FLUSHDB completed on db{current_db}")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Flush failed: {exc}")
