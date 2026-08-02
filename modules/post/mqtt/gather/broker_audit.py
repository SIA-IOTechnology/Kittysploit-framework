#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Audit MQTT broker exposure: anonymous auth, $SYS, retained, ACL signals."""

from kittysploit import *
from lib.post.mqtt.session import MqttSessionMixin
from lib.scanner.mqtt.detectors import probe_mqtt_broker
import json
import os
import time


class Module(Post, MqttSessionMixin):
    __info__ = {
        "name": "MQTT Broker Audit",
        "description": (
            "Audit an MQTT broker from a session or rhost: anonymous access, "
            "$SYS exposure, retained messages, and rough ACL signals."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.MQTT],
        "tags": ["iot", "mqtt", "gather", "audit"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "chain": {
                "produces_capabilities": ["mqtt_access", "ot_assets"],
                "suggested_followups": [
                    "post/mqtt/gather/topic_dump",
                    "payloads/singles/cmd/multi/python_mqtt_reverse",
                ],
            },
        },
    }

    session_id = OptString("", "MQTT session ID (optional if rhost is set)", False)
    duration = OptInteger(6, "Listen window for $SYS / retained samples", False)
    save_local = OptBool(True, "Save JSON audit under ./output", False)
    rhost = OptString("", "Broker host when not using an MQTT session", False)
    rport = OptPort(1883, "Broker port when not using an MQTT session", False)
    username = OptString("", "Optional broker username", False)
    password = OptString("", "Optional broker password", False)

    def check(self):
        if self._mqtt_sid() and self._mqtt_session():
            return True
        if str(self.rhost or "").strip():
            return True
        print_error("MQTT session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False

        info = self.get_mqtt_connection_info()
        host = str(info.get("host") or "")
        port = int(info.get("port") or 1883)
        print_status(f"Auditing MQTT broker {host}:{port}...")

        probe = probe_mqtt_broker(host, port, timeout=max(3.0, float(self.duration or 6)))
        findings = {
            "broker": info,
            "detected": probe.detected,
            "anonymous": probe.anonymous,
            "auth_required": probe.auth_required,
            "broker_version": probe.broker_version,
            "probe_topics": probe.topics_seen,
            "probe_error": probe.error,
            "sys_messages": [],
            "retained_samples": [],
            "risks": [],
        }

        if not probe.detected:
            print_error(probe.error or "Broker not detected")
            return False

        if probe.anonymous:
            print_warning("Anonymous access allowed")
            findings["risks"].append("anonymous_access")
        elif probe.auth_required:
            print_info("Authentication required")
        if probe.broker_version:
            print_info(f"Broker version: {probe.broker_version}")

        # Deeper dump via session/client credentials if available
        try:
            messages, _ = self.mqtt_collect_messages(
                ["$SYS/#", "#"],
                duration=max(2.0, float(self.duration or 6)),
                max_messages=200,
            )
            findings["sys_messages"] = [
                m for m in messages if str(m.get("topic", "")).startswith("$SYS/")
            ]
            findings["retained_samples"] = [m for m in messages if m.get("retain")]
            if findings["sys_messages"]:
                print_warning(
                    f"$SYS exposed — {len(findings['sys_messages'])} message(s) readable"
                )
                findings["risks"].append("sys_topic_readable")
                for m in findings["sys_messages"][:8]:
                    print_info(f"  {m['topic']}: {m['payload'][:100]}")
            if findings["retained_samples"]:
                print_info(f"Retained messages sampled: {len(findings['retained_samples'])}")
                findings["risks"].append("retained_messages_visible")
        except Exception as exc:
            print_warning(f"Live dump skipped: {exc}")

        if not findings["risks"]:
            print_success("No high-signal exposure findings in this pass")
        else:
            print_warning(f"Risk signals: {', '.join(findings['risks'])}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"mqtt_broker_audit_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(findings, fh, indent=2, ensure_ascii=False)
            print_success(f"Saved ./{path}")
        return True
