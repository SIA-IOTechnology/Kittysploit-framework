#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers for MQTT post modules (broker sessions)."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


class MqttSessionMixin:
    """Resolve paho MQTT client + broker metadata from an MQTT session."""

    def _mqtt_opt(self, name: str, default=None):
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            attr = attr.value
        return attr if attr is not None else default

    def _mqtt_sid(self) -> str:
        sid = getattr(self, "session_id", "")
        if hasattr(sid, "value"):
            sid = sid.value
        return str(sid or "").strip()

    def _mqtt_session(self):
        sid = self._mqtt_sid()
        fw = getattr(self, "framework", None)
        if not sid or not fw or not hasattr(fw, "session_manager"):
            return None
        return fw.session_manager.get_session(sid)

    def get_mqtt_connection_info(self) -> Dict[str, Any]:
        session = self._mqtt_session()
        if session and isinstance(getattr(session, "data", None), dict):
            data = session.data
            return {
                "host": data.get("host") or data.get("rhost") or "127.0.0.1",
                "port": int(data.get("port") or data.get("rport") or 1883),
                "topic": data.get("topic") or "kittysploit/cmd",
                "username": data.get("username") or "",
                "password": data.get("password") or "",
                "client_id": data.get("client_id") or "",
                "protocol": data.get("protocol") or "mqtt",
            }
        return {
            "host": str(self._mqtt_opt("rhost") or self._mqtt_opt("host") or "127.0.0.1"),
            "port": int(self._mqtt_opt("rport") or self._mqtt_opt("port") or 1883),
            "topic": str(self._mqtt_opt("topic") or "#"),
            "username": str(self._mqtt_opt("username") or ""),
            "password": str(self._mqtt_opt("password") or ""),
            "client_id": str(self._mqtt_opt("client_id") or "kittysploit-mqtt-post"),
            "protocol": "mqtt",
        }

    def get_mqtt_client(self):
        """Return live paho client from listener/session, or connect a new one."""
        session = self._mqtt_session()
        fw = getattr(self, "framework", None)
        if session and fw:
            data = getattr(session, "data", None) or {}
            listener_id = data.get("listener_id") if isinstance(data, dict) else None
            if listener_id and hasattr(fw, "active_listeners"):
                listener = fw.active_listeners.get(listener_id)
                if listener and hasattr(listener, "_session_connections"):
                    conn = listener._session_connections.get(self._mqtt_sid())
                    if conn and hasattr(conn, "publish"):
                        return conn
            if isinstance(data, dict) and data.get("connection") and hasattr(data["connection"], "publish"):
                return data["connection"]

        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise RuntimeError("paho-mqtt is required (pip install paho-mqtt)") from exc

        info = self.get_mqtt_connection_info()
        client = mqtt.Client(
            client_id=str(info.get("client_id") or "kittysploit-mqtt-post"),
            protocol=mqtt.MQTTv311,
        )
        user = str(info.get("username") or "").strip()
        if user:
            client.username_pw_set(user, str(info.get("password") or ""))
        client.connect(str(info["host"]), int(info["port"]), keepalive=60)
        client.loop_start()
        time.sleep(0.5)
        return client

    def mqtt_collect_messages(
        self,
        topics: List[str],
        duration: float = 5.0,
        *,
        client=None,
        max_messages: int = 500,
    ) -> Tuple[List[Dict[str, Any]], Any]:
        """Subscribe and collect messages for ``duration`` seconds."""
        owns_client = client is None
        client = client or self.get_mqtt_client()
        messages: List[Dict[str, Any]] = []

        def on_message(_c, _u, msg):
            if len(messages) >= max_messages:
                return
            try:
                payload = msg.payload.decode("utf-8", errors="replace")
            except Exception:
                payload = repr(msg.payload)
            messages.append(
                {
                    "topic": msg.topic,
                    "payload": payload,
                    "qos": int(getattr(msg, "qos", 0) or 0),
                    "retain": bool(getattr(msg, "retain", False)),
                }
            )

        prev = getattr(client, "on_message", None)
        client.on_message = on_message
        for topic in topics:
            try:
                client.subscribe(str(topic), qos=0)
            except Exception:
                pass
        time.sleep(max(0.5, float(duration)))
        client.on_message = prev
        if owns_client:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
        return messages, client
