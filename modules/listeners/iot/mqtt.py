#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MQTT listener - connects to an MQTT broker and creates an interactive MQTT shell session.
"""

from kittysploit import *

class Module(Listener):
    """MQTT broker listener - creates interactive MQTT shell session (publish/subscribe)."""

    __info__ = {
        'name': 'MQTT Listener',
        'description': 'Connects to an MQTT broker and creates interactive MQTT shell session (publish/subscribe)',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.MQTT,
        'references': [
            'https://mqtt.org/',
            'https://www.eclipse.org/paho/',
        ],
        'dependencies': ['paho-mqtt'],
    }

    host = OptString("127.0.0.1", "MQTT broker host", True)
    port = OptPort(1883, "MQTT broker port", True)
    username = OptString("", "Broker username (optional)", False)
    password = OptString("", "Broker password (optional)", False)
    client_id = OptString("", "Client ID (optional, auto-generated if empty)", False)
    topic = OptString("kittysploit/cmd", "Default topic for subscribe/publish", True)

    def run(self):
        """Connect to MQTT broker and create session."""
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            print_error("paho-mqtt is required but not installed")
            print_info("Install it with: pip install paho-mqtt")
            return False

        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 1883
            username = str(self.username).strip() if self.username else None
            password = str(self.password).strip() if self.password else None
            client_id = str(self.client_id).strip() if self.client_id else None
            topic = str(self.topic).strip() if self.topic else "kittysploit/cmd"

            print_status(f"Connecting to MQTT broker {host}:{port}...")

            client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
            if username:
                client.username_pw_set(username, password)

            def on_connect(client, userdata, flags, rc, *args):
                if rc == 0:
                    print_success(f"Connected to MQTT broker at {host}:{port}")
                else:
                    print_error(f"Connection failed: {rc}")

            def on_disconnect(client, userdata, rc, *args):
                if rc != 0:
                    print_warning(f"Disconnected from broker: {rc}")

            client.on_connect = on_connect
            client.on_disconnect = on_disconnect
            client.connect(host, port, keepalive=60)
            client.loop_start()

            # Wait briefly to ensure connection
            import time
            time.sleep(1.0)
            if hasattr(client, 'is_connected') and not client.is_connected():
                print_error("Failed to connect to MQTT broker")
                client.loop_stop()
                return False

            additional_data = {
                'host': host,
                'port': port,
                'topic': topic,
                'username': username or '',
                'client_id': client_id or '',
            }

            return (client, host, port, additional_data)

        except Exception as e:
            print_error(f"MQTT connection failed: {e}")
            return False

    def shutdown(self):
        """Disconnect from broker."""
        try:
            if hasattr(self, '_session_connections'):
                for session_id, conn in list(self._session_connections.items()):
                    if conn and hasattr(conn, 'loop_stop'):
                        conn.loop_stop()
                    if conn and hasattr(conn, 'disconnect'):
                        conn.disconnect()
        except Exception:
            pass
