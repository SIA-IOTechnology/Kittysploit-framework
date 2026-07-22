#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BLE analyze — rank the GATT attack surface exposed by a BLE session."""

from kittysploit import *
from lib.protocols.ble.ble_session_mixin import BleSessionMixin
from datetime import datetime
from collections import Counter, defaultdict
import json


STANDARD_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000fe59-0000-1000-8000-00805f9b34fb": "Nordic Secure DFU",
}

SENSITIVE_CHAR_HINTS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a4d-0000-1000-8000-00805f9b34fb": "HID Report",
    "00002a4b-0000-1000-8000-00805f9b34fb": "HID Report Map",
}

SECURITY_PROPERTIES = {
    "authenticated-signed-writes",
    "encrypt-read",
    "encrypt-write",
    "secure-read",
    "secure-write",
}


class Module(Post, BleSessionMixin):
    __info__ = {
        "name": "BLE GATT Attack Surface",
        "description": "Analyzes GATT services and characteristics for risky read/write/notify exposure",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.BLE,
        "tags": ["ble", "bluetooth", "iot", "analyze", "gatt", "attack-surface"],
        "references": [
            "https://www.bluetooth.com/specifications/gatt/",
            "https://attack.mitre.org/techniques/T1474/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "ble_attack_surface"],
            "cost": 0.4,
            "noise": 0.0,
            "value": 1.2,
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
                "consumes_capabilities": ["ble_gatt_map", "ble_characteristics"],
                "produces_capabilities": [
                    {"capability": "ble_attack_surface", "from_detail": ""},
                    {"capability": "risk_signals", "from_detail": "findings"},
                ],
                "option_bindings": {},
                "suggested_followups": [
                    "post/ble/manage/read_characteristic",
                    "post/ble/gather/notify_capture",
                    "post/ble/manage/write_characteristic",
                ],
            },
        },
    }

    refresh = OptBool(False, "Refresh GATT services live before analysis", False)
    include_standard = OptBool(True, "Include standard Bluetooth services in findings", False)
    top_n = OptInteger(20, "Maximum findings to display", False)
    export_json = OptString("", "Optional JSON output file", False)
    store_results = OptBool(True, "Store report in session.data['ble_gatt_attack_surface']", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.BLE.value:
            print_error(f"Session is not BLE (type: {session.session_type})")
            return False
        if bool(self.refresh):
            try:
                self.open_ble()
            except Exception as exc:
                print_error(str(exc))
                return False
        return True

    def run(self):
        session = self._resolve_session()
        if not session:
            print_error("Session not found")
            return False

        if bool(self.refresh):
            self._refresh_session_inventory(session)

        data = session.data if isinstance(session.data, dict) else {}
        services, characteristics = self._collect_inventory(data)
        if not characteristics:
            print_warning("No BLE characteristics found in session data")
            print_info("Run post/ble/gather/characteristics first, or enable REFRESH if the BLE session is live")
            return False

        report = self._build_report(session, data, services, characteristics)
        self._display_report(report)

        if bool(self.store_results):
            data["ble_gatt_attack_surface"] = report
            session.data = data

        out = str(self.export_json or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Exported to {out}")
            except OSError as exc:
                print_error(f"Export failed: {exc}")

        return True

    def _refresh_session_inventory(self, session):
        client = self.open_ble()
        services = client.get_services(refresh=True)
        service_rows = []
        char_rows = []
        for svc in services:
            svc_row = {
                "uuid": svc.uuid,
                "handle": svc.handle,
                "description": getattr(svc, "description", ""),
                "characteristics": [],
            }
            for char in svc.characteristics:
                char_row = {
                    "service_uuid": svc.uuid,
                    "uuid": char.uuid,
                    "handle": char.handle,
                    "properties": list(char.properties or []),
                    "description": getattr(char, "description", ""),
                    "descriptors": getattr(char, "descriptors", []),
                }
                svc_row["characteristics"].append({
                    "uuid": char.uuid,
                    "handle": char.handle,
                    "properties": list(char.properties or []),
                })
                char_rows.append(char_row)
            service_rows.append(svc_row)

        data = session.data if isinstance(session.data, dict) else {}
        data["services"] = service_rows
        data["ble_services"] = {"count": len(service_rows), "services": service_rows}
        data["ble_characteristics"] = {"count": len(char_rows), "characteristics": char_rows}
        session.data = data

    def _collect_inventory(self, data):
        services = []
        characteristics = []

        raw_services = data.get("services") or (data.get("ble_services") or {}).get("services") or []
        for svc in raw_services:
            service_uuid = self._norm_uuid(svc.get("uuid", ""))
            service_entry = {
                "uuid": service_uuid,
                "handle": svc.get("handle"),
                "description": svc.get("description", ""),
                "characteristic_count": len(svc.get("characteristics") or []),
            }
            services.append(service_entry)
            for char in svc.get("characteristics") or []:
                row = dict(char)
                row.setdefault("service_uuid", service_uuid)
                characteristics.append(self._normalize_characteristic(row))

        for char in (data.get("ble_characteristics") or {}).get("characteristics") or []:
            normalized = self._normalize_characteristic(char)
            key = (normalized["service_uuid"], normalized["uuid"], normalized.get("handle"))
            existing = {
                (c["service_uuid"], c["uuid"], c.get("handle"))
                for c in characteristics
            }
            if key not in existing:
                characteristics.append(normalized)

        return services, characteristics

    def _normalize_characteristic(self, char):
        return {
            "service_uuid": self._norm_uuid(char.get("service_uuid", "")),
            "uuid": self._norm_uuid(char.get("uuid", "")),
            "handle": char.get("handle"),
            "properties": self._norm_props(char.get("properties") or []),
            "description": char.get("description", ""),
            "descriptors": char.get("descriptors") or [],
        }

    def _build_report(self, session, data, services, characteristics):
        findings = []
        summary = {
            "services": len(services),
            "characteristics": len(characteristics),
            "readable": 0,
            "writable": 0,
            "write_without_response": 0,
            "notify_or_indicate": 0,
            "custom_services": 0,
            "custom_characteristics": 0,
            "security_property_hints": 0,
        }

        service_lookup = {svc["uuid"]: svc for svc in services}
        service_chars = defaultdict(list)
        for char in characteristics:
            service_chars[char["service_uuid"]].append(char)

        for svc in services:
            if not self._is_standard_uuid(svc["uuid"]):
                summary["custom_services"] += 1

        for char in characteristics:
            props = set(char["properties"])
            service_uuid = char["service_uuid"]
            standard_service = self._is_standard_uuid(service_uuid)
            standard_char = self._is_standard_uuid(char["uuid"])

            summary["readable"] += int("read" in props)
            summary["writable"] += int("write" in props or "write-without-response" in props)
            summary["write_without_response"] += int("write-without-response" in props)
            summary["notify_or_indicate"] += int("notify" in props or "indicate" in props)
            summary["custom_characteristics"] += int(not standard_char)
            summary["security_property_hints"] += int(bool(props & SECURITY_PROPERTIES))

            if (not bool(self.include_standard)) and standard_service and standard_char:
                continue

            score, reasons, severity = self._score_characteristic(char, service_lookup.get(service_uuid))
            if score <= 0:
                continue

            findings.append({
                "severity": severity,
                "score": round(score, 2),
                "service_uuid": service_uuid,
                "service_name": STANDARD_SERVICES.get(service_uuid, "Custom/Unknown"),
                "uuid": char["uuid"],
                "handle": char.get("handle"),
                "description": char.get("description") or SENSITIVE_CHAR_HINTS.get(char["uuid"], ""),
                "properties": char["properties"],
                "reasons": reasons,
                "recommended_followups": self._followups(char),
            })

        for service_uuid, chars in service_chars.items():
            if len(chars) >= 4 and not self._is_standard_uuid(service_uuid):
                findings.append({
                    "severity": "medium",
                    "score": 0.55,
                    "service_uuid": service_uuid,
                    "service_name": "Custom/Unknown",
                    "uuid": "",
                    "handle": None,
                    "description": "Custom service with multiple characteristics",
                    "properties": [],
                    "reasons": [
                        f"custom service exposes {len(chars)} characteristics",
                        "likely vendor protocol surface",
                    ],
                    "recommended_followups": [
                        "post/ble/gather/characteristics",
                        "post/ble/manage/read_characteristic for readable UUIDs",
                    ],
                })

        findings.sort(key=lambda item: (self._severity_rank(item["severity"]), item["score"]), reverse=True)
        risk_score = self._risk_score(summary, findings)

        return {
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "session_id": getattr(session, "id", ""),
            "address": data.get("address") or getattr(session, "host", ""),
            "name": data.get("name", ""),
            "adapter": data.get("adapter", ""),
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "summary": summary,
            "property_counts": dict(Counter(prop for c in characteristics for prop in c["properties"])),
            "findings": findings,
        }

    def _score_characteristic(self, char, service):
        props = set(char["properties"])
        reasons = []
        score = 0.0

        if "write-without-response" in props:
            score += 0.45
            reasons.append("writable without response/ack")
        if "write" in props:
            score += 0.35
            reasons.append("writable characteristic")
        if "read" in props:
            score += 0.15
            reasons.append("readable characteristic")
        if "notify" in props or "indicate" in props:
            score += 0.2
            reasons.append("notification/indication channel")
        if ("write" in props or "write-without-response" in props) and ("notify" in props or "indicate" in props):
            score += 0.25
            reasons.append("write plus notify can expose command/response workflow")
        if ("write" in props or "write-without-response" in props) and "read" in props:
            score += 0.15
            reasons.append("read/write characteristic can expose state mutation")
        if not self._is_standard_uuid(char["uuid"]):
            score += 0.15
            reasons.append("custom/vendor characteristic")
        if service and not self._is_standard_uuid(service.get("uuid", "")):
            score += 0.15
            reasons.append("custom/vendor service")
        if char["uuid"] in SENSITIVE_CHAR_HINTS:
            score += 0.1
            reasons.append(f"sensitive standard field: {SENSITIVE_CHAR_HINTS[char['uuid']]}")
        if props & SECURITY_PROPERTIES:
            score -= 0.15
            reasons.append("properties hint at authenticated/encrypted access")

        score = max(0.0, min(1.0, score))
        if score >= 0.75:
            severity = "high"
        elif score >= 0.45:
            severity = "medium"
        else:
            severity = "low"
        return score, reasons, severity

    def _followups(self, char):
        props = set(char["properties"])
        uuid = char["uuid"]
        followups = []
        if "read" in props:
            followups.append(f"post/ble/manage/read_characteristic UUID={uuid}")
        if "notify" in props or "indicate" in props:
            followups.append(f"post/ble/gather/notify_capture UUID={uuid}")
        if "write" in props or "write-without-response" in props:
            followups.append(f"post/ble/manage/write_characteristic UUID={uuid} DRY_RUN=true")
        return followups

    def _display_report(self, report):
        summary = report["summary"]
        findings = report["findings"]
        top_n = max(1, int(self.top_n or 20))

        print_info("=" * 80)
        print_success("BLE GATT Attack Surface")
        print_info(f"  Device    : {report.get('address')} {report.get('name') or ''}".rstrip())
        print_info(f"  Risk      : {report['risk_level']} ({report['risk_score']}/100)")
        print_info(f"  Services  : {summary['services']} ({summary['custom_services']} custom)")
        print_info(f"  Chars     : {summary['characteristics']} ({summary['custom_characteristics']} custom)")
        print_info(
            "  Exposure  : "
            f"read={summary['readable']} write={summary['writable']} "
            f"wwr={summary['write_without_response']} notify={summary['notify_or_indicate']}"
        )
        print_info("=" * 80)

        if not findings:
            print_success("No notable GATT attack-surface findings")
            return

        print_status(f"Top findings ({min(top_n, len(findings))}/{len(findings)})")
        print_info("-" * 80)
        print_info(f"{'Sev':<7} {'Score':>5} {'UUID':<38} {'Props':<24} Reasons")
        print_info("-" * 80)
        for finding in findings[:top_n]:
            props = ",".join(finding["properties"]) or "-"
            if len(props) > 22:
                props = props[:20] + ".."
            reasons = "; ".join(finding["reasons"])
            print_info(
                f"{finding['severity']:<7} {finding['score']:>5.2f} "
                f"{finding['uuid'] or finding['service_uuid']:<38} {props:<24} {reasons}"
            )

        print_info("-" * 80)
        print_status("Suggested followups")
        suggestions = []
        for finding in findings:
            for followup in finding.get("recommended_followups") or []:
                if followup not in suggestions:
                    suggestions.append(followup)
                if len(suggestions) >= 8:
                    break
            if len(suggestions) >= 8:
                break
        for item in suggestions:
            print_info(f"  {item}")

    def _risk_score(self, summary, findings):
        score = 0
        score += min(25, summary["writable"] * 5)
        score += min(20, summary["write_without_response"] * 6)
        score += min(15, summary["notify_or_indicate"] * 3)
        score += min(15, summary["custom_services"] * 4)
        score += min(15, summary["custom_characteristics"] * 2)
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        score += min(10, high * 4 + medium * 2)
        return min(100, int(score))

    def _risk_level(self, score):
        if score >= 70:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def _severity_rank(self, severity):
        return {"low": 1, "medium": 2, "high": 3}.get(str(severity), 0)

    def _is_standard_uuid(self, uuid):
        uuid = self._norm_uuid(uuid)
        if not uuid:
            return False
        return uuid.startswith("0000") and uuid.endswith("-0000-1000-8000-00805f9b34fb")

    def _norm_uuid(self, value):
        text = str(value or "").strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        if len(text) == 4 and all(c in "0123456789abcdef" for c in text):
            return f"0000{text}-0000-1000-8000-00805f9b34fb"
        return text

    def _norm_props(self, props):
        result = []
        for prop in props or []:
            item = str(prop or "").strip().lower().replace("_", "-")
            if item and item not in result:
                result.append(item)
        return result
