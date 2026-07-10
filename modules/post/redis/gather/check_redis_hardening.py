from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient


class Module(Post, RedisClient):

	__info__ = {
		"name": "Check Redis Hardening",
		"description": "Audit common Redis security misconfigurations",
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

	WEBROOT_HINTS = (
		"/var/www",
		"/usr/share/nginx",
		"/home/www",
		"/srv/www",
		"/app/public",
		"/public_html",
		"htdocs",
		"wwwroot",
	)

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Redis hardening audit")
			print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)}")

			server_info = self.get_info("server")
			if server_info.get("redis_version"):
				print_info(f"Version: {server_info['redis_version']}")
			if server_info.get("os"):
				print_info(f"OS: {server_info['os']}")

			config = {}
			try:
				config = self.get_config("*")
			except ProcedureError as exc:
				print_warning(f"Cannot read configuration: {exc}")

			print_info("=" * 80)
			self._check_authentication(config, info)
			self._check_network_exposure(config)
			self._check_config_commands(config)
			self._check_persistence_paths(config)
			self._check_replication(config)
			self._check_modules(config, server_info)

			print_info("=" * 80)
			print_success("Hardening audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Hardening audit failed: {exc}"
			)

	def _check_authentication(self, config: dict, session_info: dict):
		print_info("-" * 80)
		print_status("Check: Authentication")

		requirepass = str(config.get("requirepass", "") or "").strip()
		session_password = str(session_info.get("password", "") or "").strip()

		if requirepass:
			print_success("requirepass is configured")
		elif session_password:
			print_success("Session authenticated (ACL or legacy auth)")
		else:
			print_error("No password protection detected")

		protected_mode = str(config.get("protected-mode", "")).lower()
		if protected_mode == "yes":
			print_success("protected-mode is enabled")
		elif protected_mode == "no":
			print_warning("protected-mode is disabled")
		else:
			print_info(f"protected-mode: {protected_mode or '(unknown)'}")

	def _check_network_exposure(self, config: dict):
		print_info("-" * 80)
		print_status("Check: Network exposure")

		bind = str(config.get("bind", "") or "").strip()
		if not bind:
			print_warning("bind is empty (default listen behavior depends on protected-mode)")
		elif bind in ("0.0.0.0", "*", "::", "-::1"):
			print_error(f"Redis binds to all interfaces (bind={bind})")
		else:
			print_success(f"bind={bind}")

		port = config.get("port", "6379")
		print_info(f"port: {port}")

	def _check_config_commands(self, config: dict):
		print_info("-" * 80)
		print_status("Check: Dangerous commands")

		renamed = [
			key for key in config
			if key.startswith("rename-command")
		]
		if renamed:
			print_success(f"{len(renamed)} command rename(s) configured")
			for key in sorted(renamed):
				value = config.get(key, "")
				if str(value).strip() in ('""', "''"):
					print_success(f"  {key}: disabled")
				else:
					print_info(f"  {key}: {value}")
		else:
			print_warning("No rename-command entries found (CONFIG/FLUSH/SLAVEOF may be available)")

		if self.config_get_allowed():
			print_error("CONFIG GET is allowed (file write RCE may be possible)")
		else:
			print_success("CONFIG GET appears restricted")

	def _check_persistence_paths(self, config: dict):
		print_info("-" * 80)
		print_status("Check: Persistence paths")

		data_dir = str(config.get("dir", "") or "").strip()
		dbfilename = str(config.get("dbfilename", "") or "").strip()

		if data_dir:
			print_info(f"dir: {data_dir}")
			lower_dir = data_dir.lower()
			if any(hint in lower_dir for hint in self.WEBROOT_HINTS):
				print_error(f"Data directory looks like a web root ({data_dir})")
			elif data_dir in ("/", "/tmp", "/var/tmp"):
				print_warning(f"Writable-looking data directory: {data_dir}")
			else:
				print_success(f"Data directory: {data_dir}")
		else:
			print_warning("dir not available")

		if dbfilename:
			print_info(f"dbfilename: {dbfilename}")

	def _check_replication(self, config: dict):
		print_info("-" * 80)
		print_status("Check: Replication")

		replication = self.get_info("replication")
		role = replication.get("role", "unknown")
		print_info(f"role: {role}")

		if role == "master":
			slaves = replication.get("connected_slaves", 0)
			print_info(f"connected_slaves: {slaves}")
		elif role in ("slave", "replica"):
			master_host = replication.get("master_host", "")
			master_port = replication.get("master_port", "")
			if master_host:
				print_info(f"master: {master_host}:{master_port}")

		masterauth = str(config.get("masterauth", "") or "").strip()
		if masterauth:
			print_success("masterauth is configured")
		elif role in ("slave", "replica"):
			print_warning("Replica without masterauth configured")

	def _check_modules(self, config: dict, server_info: dict):
		print_info("-" * 80)
		print_status("Check: Modules")

		modules_info = self.get_info("modules")
		module_count = len(modules_info) if modules_info else 0
		if module_count:
			print_warning(f"{module_count} loaded module(s) detected")
			for name, details in modules_info.items():
				if isinstance(details, dict):
					print_info(f"  {name}: {details.get('ver', 'unknown')}")
				else:
					print_info(f"  {name}")
		else:
			print_success("No loaded modules reported")

		loadmodule = str(config.get("loadmodule", "") or "").strip()
		if loadmodule:
			print_warning(f"loadmodule configured: {loadmodule}")

		enable_module = str(config.get("enable-module-command", "") or "").strip()
		if enable_module and enable_module.lower() not in ("no", "local"):
			print_warning(f"enable-module-command: {enable_module}")
