#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MQTT broker detection helpers."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MqttProbeResult:
    host: str
    port: int
    detected: bool = False
    anonymous: bool = False
    auth_required: bool = False
    broker_version: str = ""
    topics_seen: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "detected": self.detected,
            "anonymous": self.anonymous,
            "auth_required": self.auth_required,
            "broker_version": self.broker_version,
            "topics_seen": self.topics_seen,
            "error": self.error,
        }


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex((host, int(port))) == 0
    except Exception:
        return False
    finally:
        sock.close()


def probe_mqtt_broker(
    host: str,
    port: int = 1883,
    timeout: float = 5.0,
    probe_topics: Optional[List[str]] = None,
) -> MqttProbeResult:
    result = MqttProbeResult(host=host, port=int(port))
    if not _tcp_open(host, port, timeout):
        result.error = "TCP port closed"
        return result

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        result.error = "paho-mqtt not installed"
        return result

    topics = probe_topics or ["$SYS/broker/version", "$SYS/#"]
    state = {"rc": -1, "ok": False}
    messages: List[str] = []

    def on_connect(client, userdata, flags, rc, *args):
        state["rc"] = rc
        state["ok"] = rc == 0
        if rc == 0:
            for topic in topics:
                try:
                    client.subscribe(topic, qos=0)
                except Exception:
                    pass

    def on_message(client, userdata, msg):
        messages.append(msg.topic)
        payload = (msg.payload or b"")[:200]
        if "broker/version" in msg.topic and payload and not result.broker_version:
            result.broker_version = payload.decode("utf-8", errors="replace").strip()

    client = mqtt.Client(client_id="kittysploit-mqtt-probe", protocol=mqtt.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(host, int(port), keepalive=int(timeout))
        client.loop_start()
        time.sleep(min(timeout, 4.0))
        client.loop_stop()
        client.disconnect()
    except Exception as exc:
        result.error = str(exc)
        return result

    result.detected = True
    if state["ok"]:
        result.anonymous = True
        result.topics_seen = sorted(set(messages))[:20]
    elif state["rc"] in (4, 5):
        result.auth_required = True
    else:
        result.error = f"MQTT connection failed rc={state['rc']}"
    return result


def probe_mqtt_broker_tls(
    host: str,
    port: int = 8883,
    timeout: float = 5.0,
    probe_topics: Optional[List[str]] = None,
) -> MqttProbeResult:
    """Probe MQTT over TLS (typical MQTTS port 8883)."""
    result = MqttProbeResult(host=host, port=int(port))
    if not _tcp_open(host, port, timeout):
        result.error = "TCP port closed"
        return result

    try:
        import paho.mqtt.client as mqtt
        import ssl
    except ImportError as exc:
        result.error = f"dependency_missing: {exc}"
        return result

    topics = probe_topics or ["$SYS/broker/version", "$SYS/#"]
    state = {"rc": -1, "ok": False}
    messages: List[str] = []

    def on_connect(client, userdata, flags, rc, *args):
        state["rc"] = rc
        state["ok"] = rc == 0
        if rc == 0:
            for topic in topics:
                try:
                    client.subscribe(topic, qos=0)
                except Exception:
                    pass

    def on_message(client, userdata, msg):
        messages.append(msg.topic)
        payload = (msg.payload or b"")[:200]
        if "broker/version" in msg.topic and payload and not result.broker_version:
            result.broker_version = payload.decode("utf-8", errors="replace").strip()

    client = mqtt.Client(client_id="kittysploit-mqtts-probe", protocol=mqtt.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)
        client.connect(host, int(port), keepalive=int(timeout))
        client.loop_start()
        time.sleep(min(timeout, 4.0))
        client.loop_stop()
        client.disconnect()
    except Exception as exc:
        result.error = str(exc)
        return result

    result.detected = True
    if state["ok"]:
        result.anonymous = True
        result.topics_seen = sorted(set(messages))[:20]
    elif state["rc"] in (4, 5):
        result.auth_required = True
    else:
        result.error = f"MQTTS connection failed rc={state['rc']}"
    return result
