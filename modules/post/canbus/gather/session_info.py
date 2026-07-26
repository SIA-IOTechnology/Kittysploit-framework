#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CANBUS Session Info - Displays metadata and statistics for a CANBUS session
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
from core.output_handler import print_info, print_success, print_error, print_warning, print_status
from datetime import datetime
import json


class Module(Post):
    """Display CANBUS session metadata and traffic statistics"""

    __info__ = {
        "name": "CANBUS Session Info",
        "description": "Displays interface, CAN ID, timing, and message statistics for a CANBUS session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
        "tags": ["canbus", "gather", "session"],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["session_metadata"],
            "cost": 0.2,
            "noise": 0.0,
            "value": 0.8,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "canbus_session", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "post/canbus/gather/ecu_discovery",
                    "post/canbus/gather/analyze_messages",
                    "post/canbus/analyze/replay_candidates",
                ],
            },
        },
    }

    show_samples = OptBool(True, "Show recent message samples", required=True)
    sample_count = OptInteger(5, "Number of recent message samples to display", required=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def check(self):
        """Check if session is a CANBUS session"""
        try:
            session_id_value = str(self.session_id)
            if not session_id_value:
                print_error("Session ID not set")
                return False

            if self.framework and hasattr(self.framework, "session_manager"):
                session = self.framework.session_manager.get_session(session_id_value)
                if session:
                    if session.session_type == "canbus":
                        return True
                    print_error(f"Session is not a CANBUS session (type: {session.session_type})")
                    return False
                print_error("Session not found")
                return False

            print_warning("Session manager not available - assuming valid session")
            return True
        except Exception as e:
            print_error(f"Error checking session: {e}")
            return False

    def run(self):
        """Display CANBUS session information"""
        try:
            session_id_value = str(self.session_id)

            if not self.framework or not hasattr(self.framework, "session_manager"):
                print_error("Framework or session manager not available")
                return False

            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                print_error("Session not found")
                return False

            data = session.data or {}
            messages = data.get("messages", []) or []
            can_id = data.get("can_id")
            can_id_hex = data.get("can_id_hex") or (f"0x{can_id:03X}" if isinstance(can_id, int) else "unknown")

            info = {
                "session_id": session_id_value,
                "host": getattr(session, "host", None),
                "port": getattr(session, "port", None),
                "session_type": session.session_type,
                "can_id": can_id,
                "can_id_hex": can_id_hex,
                "is_extended": data.get("is_extended", False),
                "is_remote": data.get("is_remote", False),
                "interface": data.get("interface"),
                "channel": data.get("channel"),
                "bitrate": data.get("bitrate"),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "message_count": data.get("message_count", len(messages)),
                "buffered_messages": len(messages),
                "unique_payloads": len({m.get("data", "") for m in messages}),
                "sibling_sessions": self._count_sibling_sessions(session),
            }

            timing = self._timing_stats(messages)
            info["timing"] = timing

            print_info("=" * 80)
            print_success("CANBUS Session Information")
            print_info("=" * 80)

            print_status("Session")
            print_info(f"  Session ID     : {info['session_id']}")
            print_info(f"  Host / bus     : {info['host']}")
            print_info(f"  Port (CAN ID)  : {info['port']}")
            print_info(f"  Type           : {info['session_type']}")

            print_info("")
            print_status("Bus configuration")
            print_info(f"  Interface      : {info['interface']}")
            print_info(f"  Channel        : {info['channel']}")
            print_info(f"  Bitrate        : {info['bitrate']} bps" if info["bitrate"] else "  Bitrate        : unknown")
            print_info(f"  CAN ID         : {can_id_hex}" + (f" ({can_id})" if can_id is not None else ""))
            print_info(f"  Extended ID    : {info['is_extended']}")
            print_info(f"  Remote frame   : {info['is_remote']}")

            print_info("")
            print_status("Traffic")
            print_info(f"  First seen     : {self._fmt_ts(info['first_seen'])}")
            print_info(f"  Last seen      : {self._fmt_ts(info['last_seen'])}")
            print_info(f"  Message count  : {info['message_count']}")
            print_info(f"  Buffered msgs  : {info['buffered_messages']}")
            print_info(f"  Unique payloads: {info['unique_payloads']}")
            print_info(f"  Sibling sessions (same bus): {info['sibling_sessions']}")

            if timing:
                print_info("")
                print_status("Timing (buffered messages)")
                print_info(f"  Avg interval   : {timing['average_interval']:.4f} s")
                print_info(f"  Min interval   : {timing['min_interval']:.4f} s")
                print_info(f"  Max interval   : {timing['max_interval']:.4f} s")
                print_info(f"  Message rate   : {timing['message_rate']:.2f} msg/s")

            if self.show_samples and messages:
                print_info("")
                print_status(f"Recent samples (last {min(int(self.sample_count), len(messages))})")
                for msg in messages[-int(self.sample_count):]:
                    ts = self._fmt_ts(msg.get("timestamp"))
                    payload = msg.get("data", "")
                    print_info(f"  [{ts}] {payload.upper() or '(empty)'}")

            if self.output_file:
                try:
                    export = dict(info)
                    export["exported_at"] = datetime.now().isoformat()
                    if self.show_samples:
                        export["samples"] = messages[-int(self.sample_count):]
                    with open(str(self.output_file), "w") as f:
                        json.dump(export, f, indent=2, default=str)
                    print_success(f"\nSession info saved to: {self.output_file}")
                except Exception as e:
                    print_error(f"Error saving results: {e}")

            print_info("=" * 80)
            print_success("CANBUS session info completed")
            return True

        except Exception as e:
            print_error(f"Error reading CANBUS session info: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _count_sibling_sessions(self, session) -> int:
        """Count other canbus sessions on the same interface:channel."""
        try:
            data = session.data or {}
            interface = data.get("interface")
            channel = data.get("channel")
            if not interface and not channel:
                return 0

            count = 0
            for other in self.framework.session_manager.get_sessions():
                if other.id == session.id or other.session_type != "canbus":
                    continue
                odata = other.data or {}
                if odata.get("interface") == interface and odata.get("channel") == channel:
                    count += 1
            return count
        except Exception:
            return 0

    def _timing_stats(self, messages):
        if len(messages) < 2:
            return None

        timestamps = [m.get("timestamp", 0) or 0 for m in messages]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        span = timestamps[-1] - timestamps[0]
        return {
            "average_interval": sum(intervals) / len(intervals) if intervals else 0,
            "min_interval": min(intervals) if intervals else 0,
            "max_interval": max(intervals) if intervals else 0,
            "message_rate": (len(messages) / span) if span > 0 else 0,
        }

    def _fmt_ts(self, value):
        if value is None:
            return "n/a"
        try:
            ts = float(value)
            # python-can timestamps are usually epoch floats
            if ts > 1e9:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            return f"{ts:.6f}"
        except Exception:
            return str(value)
