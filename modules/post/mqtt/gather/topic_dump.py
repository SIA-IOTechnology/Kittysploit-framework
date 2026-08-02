#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dump MQTT topics / retained messages from a broker session or direct connect."""

from kittysploit import *
from lib.post.mqtt.session import MqttSessionMixin
import json
import os
import time


class Module(Post, MqttSessionMixin):
    __info__ = {
        "name": "MQTT Topic Dump",
        "description": (
            "Subscribe to broker topics (default # and $SYS/#) for a short window "
            "and dump messages seen — including retained. Works on MQTT sessions "
            "or with rhost/rport."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "session_type": [SessionType.MQTT],
        "tags": ["iot", "mqtt", "gather"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "reconnaissance"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "chain": {
                "produces_capabilities": ["mqtt_access", "ot_assets"],
                "consumes_capabilities": ["mqtt_access"],
                "suggested_followups": ["post/mqtt/gather/broker_audit"],
            },
            "requires": {"capabilities_any": ["mqtt_access"]},
        },
    }

    session_id = OptString("", "MQTT session ID (optional if rhost is set)", False)
    topics = OptString("#,$SYS/#", "Comma-separated subscribe filters", False)
    duration = OptInteger(8, "Seconds to listen for messages", False)
    max_messages = OptInteger(500, "Maximum messages to capture", False)
    save_local = OptBool(True, "Save JSON dump under ./output", False)
    rhost = OptString("", "Broker host when not using an MQTT session", False)
    rport = OptPort(1883, "Broker port when not using an MQTT session", False)
    username = OptString("", "Optional broker username", False)
    password = OptString("", "Optional broker password", False)

    def check(self):
        sid = self._mqtt_sid()
        if sid and self._mqtt_session():
            return True
        host = str(self.rhost or "").strip()
        if host:
            return True
        print_error("MQTT session_id or rhost is required")
        return False

    def run(self):
        if not self.check():
            return False

        topic_list = [
            t.strip() for t in str(self.topics or "#,$SYS/#").split(",") if t.strip()
        ]
        duration = max(1, int(self.duration or 8))
        max_msg = max(10, int(self.max_messages or 500))

        info = self.get_mqtt_connection_info()
        print_status(
            f"Dumping MQTT topics on {info.get('host')}:{info.get('port')} "
            f"for {duration}s — filters: {', '.join(topic_list)}"
        )

        try:
            messages, _ = self.mqtt_collect_messages(
                topic_list, duration=duration, max_messages=max_msg
            )
        except Exception as exc:
            print_error(str(exc))
            return False

        if not messages:
            print_warning("No messages received (broker quiet, ACL deny, or wrong filters)")
            return True

        retained = [m for m in messages if m.get("retain")]
        topics_seen = sorted({m["topic"] for m in messages})
        print_success(
            f"Captured {len(messages)} message(s) across {len(topics_seen)} topic(s) "
            f"({len(retained)} retained)"
        )
        for topic in topics_seen[:40]:
            count = sum(1 for m in messages if m["topic"] == topic)
            print_info(f"  [{count:3d}] {topic}")
        if len(topics_seen) > 40:
            print_info(f"  ... {len(topics_seen) - 40} more topics")

        # Show sample payloads
        for msg in messages[:15]:
            payload = msg["payload"]
            preview = payload if len(payload) <= 120 else payload[:117] + "..."
            flag = " R" if msg.get("retain") else ""
            print_info(f"  {msg['topic']}{flag}: {preview}")

        if bool(self.save_local):
            os.makedirs("output", exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join("output", f"mqtt_topic_dump_{stamp}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "broker": info,
                        "filters": topic_list,
                        "duration": duration,
                        "topics": topics_seen,
                        "messages": messages,
                    },
                    fh,
                    indent=2,
                    ensure_ascii=False,
                )
            print_success(f"Saved ./{path}")
        return True
