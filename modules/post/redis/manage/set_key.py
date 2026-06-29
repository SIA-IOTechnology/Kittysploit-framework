from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Set Key",
		"description": "Create or overwrite a string key in the current Redis database",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['target_modification'],
	    'expected_requests': 1,
	    'reversible': True,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	},
	}

	key = OptString("", "Key name", True)
	value = OptString("", "String value to store", True)
	ttl = OptInteger(0, "TTL in seconds (0 = no expiration)", False)
	db = OptInteger(-1, "Database index (0-15, -1 = keep current)", False)
	overwrite = OptBool(True, "Allow overwriting an existing key", False)

	def run(self):
		try:
			key = str(self.key or "").strip()
			value = str(self.value if self.value is not None else "")
			if not key:
				raise ProcedureError(FailureType.ConfigurationError, "key is required")

			if self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")

			key_type = self.get_key_type(key)
			if key_type not in ("none", "string"):
				raise ProcedureError(
					FailureType.NotAccess,
					f"Key {key!r} already exists with type {key_type!r} (string only)",
				)
			if key_type == "string" and not self.overwrite:
				raise ProcedureError(
					FailureType.NotAccess,
					f"Key {key!r} already exists (set overwrite=True to replace)",
				)

			ex = int(self.ttl) if self.ttl and int(self.ttl) > 0 else None
			if self.set_string(key, value, ex=ex):
				print_success(f"Set {key!r}")
				if ex:
					print_info(f"  TTL: {ex}s")
				return True

			raise ProcedureError(FailureType.Unknown, f"Failed to set key {key!r}")
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Set key failed: {exc}")
