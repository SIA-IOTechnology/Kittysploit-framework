from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Redis Modify ACL",
		"description": "List, inspect, create, update, or delete Redis ACL users (Redis 6+)",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['target_modification', 'configuration_change'],
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

	action = OptString("list", "Action: list, get, set, del", False)
	username = OptString("", "ACL username (required for get/set/del)", False)
	password = OptString("", "Password for ACL SETUSER (prefix with > in rules if omitted)", False)
	enabled = OptBool(True, "Enable user when action=set", False)
	reset = OptBool(True, "Reset user rules before applying action=set", False)
	rules = OptString("+@all ~* &*", "Extra ACL SETUSER rule tokens (space-separated)", False)
	confirm = OptBool(False, "Skip confirmation for set/del", False)

	def run(self):
		try:
			action = str(self.action or "list").strip().lower()
			if action not in ("list", "get", "set", "del"):
				raise ProcedureError(
					FailureType.ConfigurationError,
					"action must be list, get, set, or del",
				)

			info = self.get_session_info()
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)}")

			if action == "list":
				return self._action_list()
			if action == "get":
				return self._action_get()
			if action == "set":
				return self._action_set()
			return self._action_del()
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"ACL modification failed: {exc}")

	def _action_list(self):
		entries = self.acl_list()
		if not entries:
			print_warning("No ACL users returned")
			return True
		print_success(f"Found {len(entries)} ACL user(s):")
		for entry in entries:
			print_info(f"  {entry}")
		return True

	def _action_get(self):
		username = self._require_username()
		rows = self.acl_getuser(username)
		if not rows:
			print_warning(f"User {username!r} not found or empty response")
			return True
		print_success(f"ACL user {username!r}:")
		for row in rows:
			print_info(f"  {row}")
		return True

	def _action_set(self):
		username = self._require_username()
		tokens = []
		if self.reset:
			tokens.append("reset")
		tokens.append("on" if self.enabled else "off")

		password = str(self.password or "").strip()
		if password:
			if not password.startswith(">"):
				password = f">{password}"
			tokens.append(password)

		rules = str(self.rules or "").strip()
		if rules:
			tokens.extend(rules.split())

		print_info(f"ACL SETUSER {username} {' '.join(tokens)}")
		if not self.confirm:
			print_warning("This will modify Redis ACL configuration")
			response = input("Continue? (yes/no): ").strip().lower()
			if response not in ("yes", "y"):
				print_info("ACL update cancelled")
				return False

		self.acl_setuser(username, *tokens)
		print_success(f"Updated ACL user {username!r}")
		return True

	def _action_del(self):
		username = self._require_username()
		if username in ("default",):
			raise ProcedureError(
				FailureType.NotAccess,
				"Refusing to delete the default ACL user",
			)

		if not self.confirm:
			print_warning(f"This will delete ACL user {username!r}")
			response = input("Continue? (yes/no): ").strip().lower()
			if response not in ("yes", "y"):
				print_info("ACL deletion cancelled")
				return False

		deleted = self.acl_deluser(username)
		if deleted:
			print_success(f"Deleted ACL user {username!r}")
		else:
			print_warning(f"User {username!r} was not deleted")
		return True

	def _require_username(self) -> str:
		username = str(self.username or "").strip()
		if not username:
			raise ProcedureError(
				FailureType.ConfigurationError,
				"username is required for this action",
			)
		return username
