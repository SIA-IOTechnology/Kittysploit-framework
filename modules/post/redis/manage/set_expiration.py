from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Set Expiration",
		"description": "Set EXPIRE on a key or remove expiration with PERSIST",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['target_modification'],
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

	key = OptString("", "Key name", True)
	action = OptString("expire", "Action: expire or persist", False)
	ttl = OptInteger(3600, "TTL in seconds when action=expire", False)
	db = OptInteger(-1, "Database index (0-15, -1 = keep current)", False)

	def run(self):
		try:
			key = str(self.key or "").strip()
			action = str(self.action or "expire").strip().lower()
			if not key:
				raise ProcedureError(FailureType.ConfigurationError, "key is required")
			if action not in ("expire", "persist"):
				raise ProcedureError(
					FailureType.ConfigurationError,
					"action must be expire or persist",
				)

			if self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")

			if self.get_key_type(key) == "none":
				raise ProcedureError(FailureType.NotFound, f"Key not found: {key!r}")

			previous_ttl = self.get_ttl(key)
			print_info(f"Key: {key!r} (current TTL: {previous_ttl})")

			if action == "persist":
				if self.persist_key(key):
					print_success(f"Removed expiration on {key!r}")
					return True
				raise ProcedureError(FailureType.Unknown, f"PERSIST failed for {key!r}")

			seconds = int(self.ttl) if self.ttl is not None else 3600
			if seconds <= 0:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"ttl must be greater than 0 for expire",
				)
			if self.set_expire(key, seconds):
				print_success(f"Set TTL on {key!r} to {seconds}s")
				return True

			raise ProcedureError(FailureType.Unknown, f"EXPIRE failed for {key!r}")
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Set expiration failed: {exc}")
