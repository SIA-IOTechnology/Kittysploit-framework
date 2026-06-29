from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Delete Keys",
		"description": "Delete one or more Redis keys by name or SCAN pattern",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'destructive',
	    'effects': ['target_modification'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	},
	}

	keys = OptString("", "Comma/space-separated key names to delete", False)
	pattern = OptString("", "SCAN pattern (e.g. temp:*) — requires confirm", False)
	max_keys = OptInteger(100, "Max keys to delete when using pattern", False)
	db = OptInteger(-1, "Database index (0-15, -1 = keep current)", False)
	confirm = OptBool(False, "Skip confirmation prompt", False)

	def run(self):
		try:
			if self.db is not None and int(self.db) >= 0:
				self.select_db(int(self.db))

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")

			target_keys = self._parse_keys()
			pattern = str(self.pattern or "").strip()

			if not target_keys and not pattern:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"Provide keys and/or pattern",
				)

			if pattern:
				limit = max(1, int(self.max_keys) if self.max_keys is not None else 100)
				print_status(f"Scanning keys matching {pattern!r} (max {limit})")
				target_keys.extend(self.scan_keys(pattern=pattern, max_keys=limit))

			target_keys = list(dict.fromkeys(k for k in target_keys if k))
			if not target_keys:
				print_warning("No keys matched")
				return True

			print_info(f"Keys to delete ({len(target_keys)}):")
			for key in target_keys[:20]:
				print_info(f"  {key} ({self.get_key_type(key)})")
			if len(target_keys) > 20:
				print_info(f"  ... and {len(target_keys) - 20} more")

			if not self.confirm:
				print_warning("This will permanently delete the listed keys")
				response = input("Continue? (yes/no): ").strip().lower()
				if response not in ("yes", "y"):
					print_info("Deletion cancelled")
					return False

			deleted = self.delete_keys(target_keys)
			print_success(f"Deleted {deleted} key(s)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"Delete keys failed: {exc}")

	def _parse_keys(self):
		raw = str(self.keys or "").strip()
		if not raw:
			return []
		keys = []
		for part in raw.replace(",", " ").split():
			part = part.strip()
			if part:
				keys.append(part)
		return keys
