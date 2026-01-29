#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MQTT shell implementation for MQTT sessions.
"""

import threading
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class MQTTShell(BaseShell):
    """MQTT shell - publish/subscribe and view messages."""

    def __init__(self, session_id: str, session_type: str = "mqtt", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.client = None
        self.host = "localhost"
        self.port = 1883
        self.topic = "kittysploit/cmd"
        self._messages: List[Dict[str, Any]] = []
        self._messages_lock = threading.Lock()

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'info': self._cmd_info,
            'publish': self._cmd_publish,
            'pub': self._cmd_publish,
            'subscribe': self._cmd_subscribe,
            'sub': self._cmd_subscribe,
            'unsubscribe': self._cmd_unsubscribe,
            'unsub': self._cmd_unsubscribe,
            'messages': self._cmd_messages,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_mqtt_connection()

    def _on_message(self, client, userdata, msg):
        """Store incoming MQTT messages."""
        try:
            payload = msg.payload.decode('utf-8', errors='replace') if isinstance(msg.payload, bytes) else str(msg.payload)
            with self._messages_lock:
                self._messages.append({
                    'topic': msg.topic,
                    'payload': payload,
                    'qos': getattr(msg, 'qos', 0),
                })
                if len(self._messages) > 100:
                    self._messages.pop(0)
        except Exception:
            pass

    def _initialize_mqtt_connection(self):
        """Initialize MQTT client from session/listener."""
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 1883)
                    self.topic = session.data.get('topic', 'kittysploit/cmd')
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and hasattr(conn, 'publish'):
                                self.client = conn
                                conn.on_message = self._on_message
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if conn and hasattr(conn, 'publish'):
                            self.client = conn
                            conn.on_message = self._on_message
        except Exception as e:
            print_warning(f"Could not initialize MQTT connection: {e}")

    @property
    def shell_name(self) -> str:
        return "mqtt"

    @property
    def prompt_template(self) -> str:
        return f"mqtt [{self.host}:{self.port}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': str(e)}
        return {'output': '', 'status': 1, 'error': f"Unknown command: {cmd}. Use 'help'."}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
MQTT Shell Commands:
====================
  publish <topic> <payload>  - Publish message (alias: pub)
  subscribe <topic>          - Subscribe to topic (alias: sub)
  unsubscribe <topic>       - Unsubscribe from topic (alias: unsub)
  messages [N]               - Show last N received messages (default 10)
  info                      - Broker and session info
  help                      - This help
  exit, quit                 - Exit shell
"""
        return {'output': help_text.strip(), 'status': 0, 'error': ''}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        return {'output': '', 'status': 0, 'error': ''}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        history = self.get_history()
        if not history:
            return {'output': 'No history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {c}" for i, c in enumerate(history)), 'status': 0, 'error': ''}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        if not self.client:
            return {'output': '', 'status': 1, 'error': 'MQTT client not available'}
        lines = [
            f"Broker:  {self.host}:{self.port}",
            f"Topic:   {self.topic}",
            f"Client:  connected" if (hasattr(self.client, 'is_connected') and self.client.is_connected()) else "Client:  (connection state unknown)",
        ]
        return {'output': '\n'.join(lines), 'status': 0, 'error': ''}

    def _cmd_publish(self, args: str) -> Dict[str, Any]:
        if not self.client:
            return {'output': '', 'status': 1, 'error': 'MQTT client not available'}
        if not args.strip():
            return {'output': '', 'status': 1, 'error': 'Usage: publish <topic> <payload>'}
        parts = args.split(None, 1)
        topic = parts[0]
        payload = parts[1] if len(parts) > 1 else ""
        try:
            result = self.client.publish(topic, payload, qos=0)
            if result and hasattr(result, 'wait_for_publish'):
                result.wait_for_publish(timeout=5)
            return {'output': f"Published to {topic}: {payload[:80]}{'...' if len(payload) > 80 else ''}", 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_subscribe(self, args: str) -> Dict[str, Any]:
        if not self.client:
            return {'output': '', 'status': 1, 'error': 'MQTT client not available'}
        topic = args.strip() if args else self.topic
        if not topic:
            return {'output': '', 'status': 1, 'error': 'Usage: subscribe <topic>'}
        try:
            result, mid = self.client.subscribe(topic, qos=0)
            if result == 0:
                return {'output': f"Subscribed to {topic}", 'status': 0, 'error': ''}
            return {'output': '', 'status': 1, 'error': f'Subscribe failed: {result}'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_unsubscribe(self, args: str) -> Dict[str, Any]:
        if not self.client:
            return {'output': '', 'status': 1, 'error': 'MQTT client not available'}
        topic = args.strip() if args else ""
        if not topic:
            return {'output': '', 'status': 1, 'error': 'Usage: unsubscribe <topic>'}
        try:
            self.client.unsubscribe(topic)
            return {'output': f"Unsubscribed from {topic}", 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_messages(self, args: str) -> Dict[str, Any]:
        try:
            n = 10
            if args.strip().isdigit():
                n = min(int(args.strip()), 100)
        except ValueError:
            n = 10
        with self._messages_lock:
            recent = self._messages[-n:] if self._messages else []
        if not recent:
            return {'output': '(no messages received yet)', 'status': 0, 'error': ''}
        lines = []
        for m in recent:
            lines.append(f"[{m['topic']}] {m['payload']}")
        return {'output': '\n'.join(lines), 'status': 0, 'error': ''}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
