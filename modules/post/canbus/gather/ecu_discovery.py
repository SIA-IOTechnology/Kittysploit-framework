#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CANBUS ECU Discovery - Discovers ECUs via passive traffic analysis and optional UDS probing
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
from core.output_handler import print_info, print_success, print_error, print_warning, print_status
from collections import defaultdict
from datetime import datetime
import json
import time


# Common ISO-TP / UDS diagnostic ID ranges (11-bit)
UDS_REQUEST_IDS = list(range(0x7E0, 0x7E8))
UDS_RESPONSE_IDS = list(range(0x7E8, 0x7F0))
UDS_FUNCTIONAL_ID = 0x7DF

# UDS services used for discovery probes
UDS_TESTER_PRESENT = bytes([0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
UDS_DIAG_SESSION = bytes([0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])


class Module(Post):
    """Discover ECUs on the CAN bus from sessions and optional active UDS probes"""

    __info__ = {
        "name": "CANBUS ECU Discovery",
        "description": (
            "Discovers ECUs by correlating CAN IDs across sessions, classifying "
            "diagnostic ranges, and optionally probing with UDS TesterPresent"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
        "tags": ["canbus", "gather", "ecu", "uds", "automotive"],
        "references": [
            "https://en.wikipedia.org/wiki/Unified_Diagnostic_Services",
            "https://en.wikipedia.org/wiki/ISO_15765-2",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon", "active_exploitation"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["ot_assets", "risk_signals"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.5,
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
                "produces_capabilities": [
                    {"capability": "ot_assets", "from_detail": "ecu_map"},
                    {"capability": "canbus_ecu_map", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "post/canbus/gather/analyze_messages",
                    "post/canbus/analyze/replay_candidates",
                    "post/canbus/gather/dump_messages",
                ],
            },
        },
    }

    mode = OptChoice(
        "passive",
        "Discovery mode: passive (sessions only), listen (sniff bus), active (UDS probe)",
        required=True,
        choices=["passive", "listen", "active"],
    )
    listen_duration = OptInteger(10, "Seconds to sniff the bus (listen/active modes)", required=True)
    probe_timeout = OptFloat(0.25, "Per-ID response timeout for active UDS probes (seconds)", required=True)
    probe_range = OptString(
        "0x7E0-0x7E7",
        "CAN ID range to probe in active mode (e.g. 0x7E0-0x7E7 or 0x700-0x7FF)",
        required=False,
    )
    include_all_sessions = OptBool(
        True,
        "Include sibling canbus sessions on the same interface:channel",
        required=True,
    )
    output_file = OptString("", "Optional JSON output file", required=False)

    def check(self):
        """Validate CANBUS session; require python-can for listen/active modes"""
        mode = str(self.mode)
        if mode in ("listen", "active"):
            try:
                import can  # noqa: F401
            except ImportError:
                print_error("python-can is required for listen/active modes")
                print_info("Install it with: pip install python-can")
                return False

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
        """Discover ECUs on the CAN bus"""
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
            interface = data.get("interface", "socketcan")
            channel = data.get("channel", "can0")
            bitrate = data.get("bitrate", 500000)
            mode = str(self.mode)

            print_info("=" * 80)
            print_success("CANBUS ECU Discovery")
            print_info(f"Mode: {mode}")
            print_info(f"Bus: {interface}:{channel} @ {bitrate} bps")
            print_info("=" * 80)

            ecus = {}

            # Passive: current + sibling sessions
            print_status("[1] Passive discovery from sessions")
            self._ingest_session(ecus, session, source="session")
            if self.include_all_sessions:
                for other in self.framework.session_manager.get_sessions():
                    if other.id == session.id or other.session_type != "canbus":
                        continue
                    odata = other.data or {}
                    if odata.get("interface") == interface and odata.get("channel") == channel:
                        self._ingest_session(ecus, other, source="sibling_session")

            print_info(f"  Known IDs from sessions: {len(ecus)}")

            # Listen / active sniff
            if mode in ("listen", "active"):
                print_status(f"[2] Listening on bus for {int(self.listen_duration)}s")
                sniffed = self._listen_bus(interface, channel, bitrate, int(self.listen_duration))
                for can_id, stats in sniffed.items():
                    self._merge_ecu(ecus, can_id, stats, source="listen")
                print_info(f"  IDs after listen: {len(ecus)}")

            # Active UDS probe
            active_hits = []
            if mode == "active":
                print_status("[3] Active UDS probing")
                print_warning("Active probes inject diagnostic frames — use only on authorized targets")
                probe_ids = self._parse_probe_range(str(self.probe_range or "0x7E0-0x7E7"))
                active_hits = self._probe_uds(
                    interface, channel, bitrate, probe_ids, float(self.probe_timeout)
                )
                for hit in active_hits:
                    req_id = hit["request_id"]
                    resp_id = hit["response_id"]
                    self._merge_ecu(
                        ecus,
                        req_id,
                        {
                            "is_extended": False,
                            "classification": "uds_request",
                            "uds_responsive": True,
                            "paired_response_id": resp_id,
                        },
                        source="uds_probe",
                    )
                    self._merge_ecu(
                        ecus,
                        resp_id,
                        {
                            "is_extended": False,
                            "classification": "uds_response",
                            "uds_responsive": True,
                            "paired_request_id": req_id,
                            "sample_response": hit.get("response_data"),
                        },
                        source="uds_probe",
                    )
                print_info(f"  Responsive ECUs: {len(active_hits)}")

            # Classify remaining IDs
            for can_id, ecu in ecus.items():
                if "classification" not in ecu or ecu["classification"] == "unknown":
                    ecu["classification"] = self._classify_id(can_id)

            results = {
                "interface": interface,
                "channel": channel,
                "bitrate": bitrate,
                "mode": mode,
                "discovered_at": datetime.now().isoformat(),
                "ecu_count": len(ecus),
                "active_hits": active_hits,
                "ecus": [self._serialize_ecu(cid, ecu) for cid, ecu in sorted(ecus.items())],
            }

            self._display_results(results)

            if self.output_file:
                try:
                    with open(str(self.output_file), "w") as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"\nResults saved to: {self.output_file}")
                except Exception as e:
                    print_error(f"Error saving results: {e}")

            # Persist discovery map on the current session
            try:
                if session.data is not None:
                    session.data["ecu_map"] = results["ecus"]
                    session.data["ecu_discovery_at"] = results["discovered_at"]
            except Exception:
                pass

            print_info("=" * 80)
            print_success(f"ECU discovery completed — {len(ecus)} ID(s) mapped")
            return True

        except Exception as e:
            print_error(f"Error during ECU discovery: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _ingest_session(self, ecus, session, source):
        data = session.data or {}
        can_id = data.get("can_id")
        if can_id is None:
            return

        messages = data.get("messages", []) or []
        payloads = [m.get("data", "") for m in messages]
        timestamps = [m.get("timestamp", 0) or 0 for m in messages]
        rate = 0.0
        if len(timestamps) >= 2 and timestamps[-1] > timestamps[0]:
            rate = len(timestamps) / (timestamps[-1] - timestamps[0])

        self._merge_ecu(
            ecus,
            int(can_id),
            {
                "is_extended": data.get("is_extended", False),
                "is_remote": data.get("is_remote", False),
                "message_count": data.get("message_count", len(messages)),
                "unique_payloads": len(set(payloads)),
                "message_rate": rate,
                "session_id": session.id,
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "sample_payloads": payloads[:5],
            },
            source=source,
        )

    def _merge_ecu(self, ecus, can_id, stats, source):
        if can_id not in ecus:
            ecus[can_id] = {
                "can_id": can_id,
                "can_id_hex": f"0x{can_id:03X}" if can_id <= 0x7FF else f"0x{can_id:08X}",
                "sources": set(),
                "classification": stats.get("classification", "unknown"),
                "is_extended": stats.get("is_extended", False),
                "is_remote": stats.get("is_remote", False),
                "message_count": 0,
                "unique_payloads": 0,
                "message_rate": 0.0,
                "session_ids": set(),
                "sample_payloads": [],
            }

        ecu = ecus[can_id]
        ecu["sources"].add(source)
        if stats.get("classification"):
            ecu["classification"] = stats["classification"]
        for key in ("uds_responsive", "paired_response_id", "paired_request_id", "sample_response"):
            if key in stats:
                ecu[key] = stats[key]
        ecu["message_count"] = max(ecu["message_count"], int(stats.get("message_count") or 0))
        ecu["unique_payloads"] = max(ecu["unique_payloads"], int(stats.get("unique_payloads") or 0))
        ecu["message_rate"] = max(ecu["message_rate"], float(stats.get("message_rate") or 0))
        if stats.get("session_id"):
            ecu["session_ids"].add(stats["session_id"])
        for payload in stats.get("sample_payloads") or []:
            if payload and payload not in ecu["sample_payloads"]:
                ecu["sample_payloads"].append(payload)
            if len(ecu["sample_payloads"]) >= 5:
                break
        if stats.get("first_seen") is not None:
            ecu["first_seen"] = stats["first_seen"]
        if stats.get("last_seen") is not None:
            ecu["last_seen"] = stats["last_seen"]

    def _classify_id(self, can_id):
        if can_id == UDS_FUNCTIONAL_ID:
            return "uds_functional"
        if can_id in UDS_REQUEST_IDS:
            return "uds_request"
        if can_id in UDS_RESPONSE_IDS:
            return "uds_response"
        if 0x700 <= can_id <= 0x7FF:
            return "diagnostic_range"
        if can_id > 0x7FF:
            return "extended"
        return "application"

    def _listen_bus(self, interface, channel, bitrate, duration):
        import can

        sniffed = defaultdict(lambda: {
            "count": 0,
            "payloads": set(),
            "is_extended": False,
            "is_remote": False,
            "first_seen": None,
            "last_seen": None,
        })

        bus = None
        try:
            bus = self._open_bus(interface, channel, bitrate)
            deadline = time.time() + max(1, duration)
            while time.time() < deadline:
                msg = bus.recv(timeout=0.1)
                if not msg:
                    continue
                entry = sniffed[msg.arbitration_id]
                entry["count"] += 1
                entry["payloads"].add(msg.data.hex())
                entry["is_extended"] = msg.is_extended_id
                entry["is_remote"] = msg.is_remote_frame
                if entry["first_seen"] is None:
                    entry["first_seen"] = msg.timestamp
                entry["last_seen"] = msg.timestamp
        finally:
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass

        result = {}
        for can_id, entry in sniffed.items():
            span = 0.0
            if entry["first_seen"] is not None and entry["last_seen"] is not None:
                span = max(0.0, entry["last_seen"] - entry["first_seen"])
            result[can_id] = {
                "is_extended": entry["is_extended"],
                "is_remote": entry["is_remote"],
                "message_count": entry["count"],
                "unique_payloads": len(entry["payloads"]),
                "message_rate": (entry["count"] / span) if span > 0 else 0.0,
                "sample_payloads": list(entry["payloads"])[:5],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
            }
        return result

    def _probe_uds(self, interface, channel, bitrate, probe_ids, timeout):
        import can

        hits = []
        bus = None
        try:
            bus = self._open_bus(interface, channel, bitrate)
            for req_id in probe_ids:
                expected_resp = req_id + 8 if req_id in UDS_REQUEST_IDS else None
                for payload in (UDS_TESTER_PRESENT, UDS_DIAG_SESSION):
                    try:
                        bus.send(
                            can.Message(
                                arbitration_id=req_id,
                                data=payload,
                                is_extended_id=False,
                                is_remote_frame=False,
                            )
                        )
                    except Exception as e:
                        print_warning(f"  Failed to send probe to 0x{req_id:03X}: {e}")
                        continue

                    deadline = time.time() + timeout
                    while time.time() < deadline:
                        msg = bus.recv(timeout=0.05)
                        if not msg:
                            continue
                        # Accept classic physical response (req+8) or any diagnostic-range reply
                        if expected_resp is not None and msg.arbitration_id == expected_resp:
                            hits.append({
                                "request_id": req_id,
                                "response_id": msg.arbitration_id,
                                "response_data": msg.data.hex().upper(),
                                "service": "0x%02X" % payload[1],
                            })
                            print_success(
                                f"  ECU response: req 0x{req_id:03X} -> "
                                f"0x{msg.arbitration_id:03X} [{msg.data.hex().upper()}]"
                            )
                            break
                        if expected_resp is None and msg.arbitration_id in UDS_RESPONSE_IDS:
                            hits.append({
                                "request_id": req_id,
                                "response_id": msg.arbitration_id,
                                "response_data": msg.data.hex().upper(),
                                "service": "0x%02X" % payload[1],
                            })
                            print_success(
                                f"  ECU response: req 0x{req_id:03X} -> "
                                f"0x{msg.arbitration_id:03X} [{msg.data.hex().upper()}]"
                            )
                            break
                    else:
                        continue
                    break  # got a hit for this req_id
        finally:
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass
        return hits

    def _open_bus(self, interface, channel, bitrate):
        import can

        if interface == "socketcan":
            return can.interface.Bus(channel=channel, bustype="socketcan")
        if interface == "virtual":
            return can.interface.Bus(channel=channel, bustype="virtual")
        return can.interface.Bus(channel=channel, bustype=interface, bitrate=bitrate)

    def _parse_probe_range(self, spec):
        spec = (spec or "").strip()
        if not spec:
            return list(UDS_REQUEST_IDS)

        if "-" in spec:
            left, right = spec.split("-", 1)
            start = self._parse_can_id(left.strip())
            end = self._parse_can_id(right.strip())
            if start is None or end is None or start > end:
                print_warning(f"Invalid probe range '{spec}', falling back to 0x7E0-0x7E7")
                return list(UDS_REQUEST_IDS)
            # Cap range size for safety
            if end - start > 512:
                print_warning("Probe range too large; capping to 512 IDs")
                end = start + 511
            return list(range(start, end + 1))

        can_id = self._parse_can_id(spec)
        return [can_id] if can_id is not None else list(UDS_REQUEST_IDS)

    def _parse_can_id(self, value):
        try:
            value = str(value).strip()
            if value.lower().startswith("0x"):
                return int(value, 16)
            if all(c in "0123456789ABCDEFabcdef" for c in value):
                return int(value, 16)
            return int(value)
        except Exception:
            return None

    def _serialize_ecu(self, can_id, ecu):
        return {
            "can_id": can_id,
            "can_id_hex": ecu["can_id_hex"],
            "classification": ecu.get("classification", "unknown"),
            "sources": sorted(ecu.get("sources") or []),
            "is_extended": ecu.get("is_extended", False),
            "is_remote": ecu.get("is_remote", False),
            "message_count": ecu.get("message_count", 0),
            "unique_payloads": ecu.get("unique_payloads", 0),
            "message_rate": round(float(ecu.get("message_rate") or 0), 4),
            "session_ids": sorted(ecu.get("session_ids") or []),
            "sample_payloads": ecu.get("sample_payloads") or [],
            "uds_responsive": ecu.get("uds_responsive", False),
            "paired_response_id": ecu.get("paired_response_id"),
            "paired_request_id": ecu.get("paired_request_id"),
            "sample_response": ecu.get("sample_response"),
        }

    def _display_results(self, results):
        print_info("")
        print_status("Discovered ECUs / CAN IDs")
        print_info("-" * 80)
        print_info(
            f"{'ID':<12} {'Class':<18} {'Msgs':>6} {'Unique':>7} {'Rate':>8} {'Sources'}"
        )
        print_info("-" * 80)

        by_class = defaultdict(int)
        for ecu in results["ecus"]:
            by_class[ecu["classification"]] += 1
            sources = ",".join(ecu["sources"][:3])
            print_info(
                f"{ecu['can_id_hex']:<12} {ecu['classification']:<18} "
                f"{ecu['message_count']:>6} {ecu['unique_payloads']:>7} "
                f"{ecu['message_rate']:>7.2f}/s {sources}"
            )

        print_info("-" * 80)
        print_status("Classification summary")
        for name, count in sorted(by_class.items(), key=lambda x: (-x[1], x[0])):
            print_info(f"  {name}: {count}")

        uds = [e for e in results["ecus"] if e.get("uds_responsive") or e["classification"].startswith("uds")]
        if uds:
            print_info("")
            print_status("Diagnostic / UDS IDs")
            for ecu in uds:
                extra = ""
                if ecu.get("paired_response_id") is not None:
                    extra = f" -> 0x{ecu['paired_response_id']:03X}"
                elif ecu.get("paired_request_id") is not None:
                    extra = f" <- 0x{ecu['paired_request_id']:03X}"
                flag = " [responsive]" if ecu.get("uds_responsive") else ""
                print_info(f"  {ecu['can_id_hex']} ({ecu['classification']}){extra}{flag}")
