from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Enumerate Redis Server Info",
		"description": "Dump Redis server, memory, replication, and persistence information",
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

	section = OptString("", "INFO section (server, memory, replication, etc.)", False)
	scan_databases = OptBool(True, "Scan all databases for non-empty key counts", False)

	SECTIONS = ("server", "clients", "memory", "persistence", "stats", "replication", "cpu", "modules")

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Session")
			for key, value in info.items():
				if key == "password" and value:
					print_info(f"  {key}: ***set***")
				else:
					print_info(f"  {key}: {value}")

			section = str(self.section).strip() if self.section else ""
			if section:
				self._print_section(section, self.get_info(section))
			else:
				for name in self.SECTIONS:
					data = self.get_info(name)
					if data:
						self._print_section(name, data)

			if self.scan_databases:
				print_info("-" * 80)
				print_status("Non-empty databases")
				db_counts = self.enumerate_databases()
				if not db_counts:
					print_info("  (all databases empty)")
				else:
					for db_index, size in db_counts:
						print_info(f"  db{db_index}: {size} key(s)")

			print_info("=" * 80)
			print_success("Redis enumeration completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error enumerating Redis info: {exc}"
			)

	def _print_section(self, name: str, data: dict):
		print_info("-" * 80)
		print_status(f"INFO {name}")
		for key, value in data.items():
			if isinstance(value, dict):
				print_info(f"  [{key}]")
				for sub_key, sub_value in value.items():
					print_info(f"    {sub_key}: {sub_value}")
			else:
				print_info(f"  {key}: {value}")
