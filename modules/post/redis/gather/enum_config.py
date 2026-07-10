from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Enumerate Redis Configuration",
		"description": "Dump security-relevant Redis server configuration",
		"author": "KittySploit Team",
		"session_type": SessionType.REDIS,
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
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	pattern = OptString("*", "CONFIG GET pattern", False)

	SENSITIVE_KEYS = frozenset({
		"requirepass",
		"masterauth",
		"tls-auth-clients",
	})

	PRIORITY_KEYS = (
		"bind",
		"protected-mode",
		"port",
		"tcp-backlog",
		"timeout",
		"requirepass",
		"masterauth",
		"dir",
		"dbfilename",
		"appendonly",
		"appendfilename",
		"save",
		"slave-read-only",
		"replica-read-only",
		"rename-command",
		"aclfile",
		"tls-port",
		"tls-cert-file",
		"tls-key-file",
		"tls-auth-clients",
		"enable-module-command",
		"loadmodule",
	)

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Session")
			print_info(f"  host: {info.get('host', 'localhost')}")
			print_info(f"  port: {info.get('port', 6379)}")
			print_info(f"  db: {info.get('db', 0)}")

			pattern = str(self.pattern).strip() if self.pattern else "*"
			print_info("-" * 80)
			print_status(f"Configuration (pattern={pattern!r})")
			config = self.get_config(pattern)
			if not config:
				print_warning("No configuration returned (CONFIG may be disabled or renamed)")
				return True

			priority = [k for k in self.PRIORITY_KEYS if k in config]
			remaining = sorted(k for k in config if k not in self.PRIORITY_KEYS)

			if priority:
				print_info("Security-relevant settings:")
				for key in priority:
					print_info(f"  {key}: {self._format_value(key, config[key])}")

			if remaining:
				print_info("Other settings:")
				for key in remaining:
					print_info(f"  {key}: {self._format_value(key, config[key])}")

			print_info("=" * 80)
			print_success(f"Retrieved {len(config)} configuration parameter(s)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating Redis configuration: {exc}"
			)

	def _format_value(self, key: str, value) -> str:
		text = str(value)
		if key in self.SENSITIVE_KEYS and text:
			return "***set***"
		if len(text) > 200:
			return text[:197] + "..."
		return text
