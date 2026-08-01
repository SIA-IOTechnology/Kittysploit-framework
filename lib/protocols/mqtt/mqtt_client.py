#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reusable MQTT over TLS client (optional mutual TLS).

Used by IoT exploits / auxiliaries that talk to brokers with client certificates
(e.g. AWS IoT Core). Depends on ``paho-mqtt``.
"""

from __future__ import annotations

import json
import ssl
import time
from pathlib import Path
from typing import Optional, Union

from core.framework.base_module import BaseModule

PathLike = Union[str, Path]


class MqttClientError(Exception):
    """MQTT connect / publish failure."""


def aws_iot_shadow_update_topic(thing_name: str) -> str:
    """Classic AWS IoT device shadow update topic."""
    name = str(thing_name or "").strip()
    if not name:
        raise ValueError("thing_name is required")
    return f"$aws/things/{name}/shadow/update"


def aws_iot_exec_command_payload(command: str, *, max_len: int = 999) -> str:
    """Build a shadow document with desired.Exec_Command (Shark/appd style)."""
    cmd = str(command or "").strip()
    if max_len > 0 and len(cmd) > max_len:
        cmd = cmd[:max_len]
    return json.dumps(
        {"state": {"desired": {"Exec_Command": cmd}}},
        separators=(",", ":"),
    )


class MqttTlsClient:
    """Minimal MQTT 3.1.1 client over TLS, with optional client certificate."""

    def __init__(
        self,
        host: str,
        port: int = 8883,
        *,
        cert_file: Optional[PathLike] = None,
        key_file: Optional[PathLike] = None,
        ca_file: Optional[PathLike] = None,
        client_id: str = "",
        insecure: bool = True,
        timeout: float = 15.0,
        keepalive: Optional[int] = None,
    ):
        self.host = str(host or "").strip()
        self.port = int(port)
        self.cert_file = Path(cert_file).expanduser() if cert_file else None
        self.key_file = Path(key_file).expanduser() if key_file else None
        self.ca_file = Path(ca_file).expanduser() if ca_file else None
        self.client_id = str(client_id or "").strip()
        self.insecure = bool(insecure)
        self.timeout = max(3.0, float(timeout))
        self.keepalive = int(keepalive) if keepalive else int(self.timeout)
        self._client = None
        self._connected = False
        self._last_rc = -1

    def validate_certs(self) -> None:
        if self.cert_file is not None and not self.cert_file.is_file():
            raise MqttClientError(f"cert_file not found: {self.cert_file}")
        if self.key_file is not None and not self.key_file.is_file():
            raise MqttClientError(f"key_file not found: {self.key_file}")
        if self.ca_file is not None and not self.ca_file.is_file():
            raise MqttClientError(f"ca_file not found: {self.ca_file}")
        if (self.cert_file is None) ^ (self.key_file is None):
            raise MqttClientError("cert_file and key_file must be set together for mTLS")

    def connect(self) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise MqttClientError(
                "paho-mqtt is required (pip install paho-mqtt)"
            ) from exc

        if not self.host:
            raise MqttClientError("host is required")
        self.validate_certs()

        state = {"rc": -1, "ok": False}

        def on_connect(client, userdata, flags, rc, *args):
            state["rc"] = rc
            state["ok"] = rc == 0

        client = mqtt.Client(
            client_id=self.client_id or "",
            protocol=mqtt.MQTTv311,
        )
        client.on_connect = on_connect

        if self.cert_file and self.key_file:
            if self.ca_file:
                client.tls_set(
                    ca_certs=str(self.ca_file),
                    certfile=str(self.cert_file),
                    keyfile=str(self.key_file),
                    cert_reqs=ssl.CERT_REQUIRED,
                    tls_version=ssl.PROTOCOL_TLS_CLIENT,
                )
                client.tls_insecure_set(False)
            else:
                client.tls_set(
                    certfile=str(self.cert_file),
                    keyfile=str(self.key_file),
                    cert_reqs=ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLS_CLIENT,
                )
                client.tls_insecure_set(self.insecure)
        else:
            # Broker TLS without client cert (optional CA)
            if self.ca_file:
                client.tls_set(
                    ca_certs=str(self.ca_file),
                    cert_reqs=ssl.CERT_REQUIRED,
                    tls_version=ssl.PROTOCOL_TLS_CLIENT,
                )
                client.tls_insecure_set(False)
            else:
                client.tls_set(cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS_CLIENT)
                client.tls_insecure_set(self.insecure)

        try:
            client.connect(self.host, self.port, keepalive=self.keepalive)
            client.loop_start()
            deadline = time.time() + self.timeout
            while time.time() < deadline and not state["ok"]:
                time.sleep(0.05)
        except Exception as exc:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
            raise MqttClientError(f"MQTT TLS connect error: {exc}") from exc

        self._last_rc = state["rc"]
        if not state["ok"]:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
            raise MqttClientError(f"MQTT connect failed (rc={state['rc']})")

        self._client = client
        self._connected = True

    @property
    def connected(self) -> bool:
        return bool(self._connected and self._client)

    def publish(self, topic: str, payload: Union[str, bytes], *, qos: int = 1) -> None:
        if not self.connected:
            raise MqttClientError("Not connected")
        topic = str(topic or "").strip()
        if not topic:
            raise MqttClientError("topic is required")
        qos = 1 if int(qos) else 0
        data = payload if isinstance(payload, (bytes, bytearray)) else str(payload)
        info = self._client.publish(topic, data, qos=qos)
        info.wait_for_publish(timeout=self.timeout)
        if getattr(info, "rc", 0) != 0:
            raise MqttClientError(f"Publish failed rc={info.rc}")

    def disconnect(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if not client:
            return
        try:
            client.loop_stop()
        except Exception:
            pass
        try:
            client.disconnect()
        except Exception:
            pass

    def __enter__(self) -> "MqttTlsClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()


class Mqtt_client(BaseModule):
    """Mixin for modules — same pattern as Tcp_client / Ssh_client / Http_client."""

    def __init__(self, framework=None):
        super().__init__(framework)

    def open_mqtt_tls(
        self,
        host: str,
        port: int = 8883,
        *,
        cert_file: Optional[PathLike] = None,
        key_file: Optional[PathLike] = None,
        ca_file: Optional[PathLike] = None,
        client_id: str = "",
        insecure: bool = True,
        timeout: float = 15.0,
        connect: bool = True,
    ) -> MqttTlsClient:
        """Create an MQTTS client (optional mTLS). Connects by default."""
        client = MqttTlsClient(
            host,
            port,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            client_id=client_id,
            insecure=insecure,
            timeout=timeout,
        )
        if connect:
            client.connect()
        return client

    @staticmethod
    def mqtt_aws_iot_shadow_update_topic(thing_name: str) -> str:
        return aws_iot_shadow_update_topic(thing_name)

    @staticmethod
    def mqtt_aws_iot_exec_command_payload(command: str, *, max_len: int = 999) -> str:
        return aws_iot_exec_command_payload(command, max_len=max_len)
