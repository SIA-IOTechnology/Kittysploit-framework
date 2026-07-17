#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DoIP DTC Read - Reads diagnostic trouble codes via UDS 0x19 over DoIP
"""

from kittysploit import *
from lib.protocols.doip.constants import UDS_DTC_REPORT_BY_STATUS_MASK
from lib.protocols.doip.doip_session_mixin import DoIPSessionMixin
import json
from datetime import datetime


def _parse_int(value, default=None):
    if value is None or value == "":
        return default
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


class Module(Post, DoIPSessionMixin):
    __info__ = {
        "name": "DoIP Read DTCs",
        "description": (
            "Reads Diagnostic Trouble Codes from an ECU over DoIP using "
            "UDS ReadDTCInformation (0x19)"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.DOIP,
        "tags": ["automotive", "doip", "gather", "dtc", "uds"],
        "references": [
            "ISO 14229-1",
            "SAE J2012",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["vehicle_diagnostics"],
            "cost": 0.6,
            "noise": 0.15,
            "value": 1.3,
            "chain": {
                "consumes_capabilities": ["doip_session"],
                "produces_capabilities": [
                    {"capability": "vehicle_diagnostics", "from_detail": "dtcs"},
                ],
                "suggested_followups": [
                    "post/automotive/doip/gather/vin",
                    "post/automotive/doip/exploits/uds_query",
                ],
            },
        },
    }

    target_address = OptString(
        "",
        "ECU logical address (hex). Empty = session default",
        required=False,
    )
    sub_function = OptString(
        "0x02",
        "ReadDTCInformation sub-function (0x02=reportDTCByStatusMask, 0x0A=supportedDTCs)",
        required=True,
    )
    status_mask = OptString(
        "0xFF",
        "DTC status mask (used by sub-functions that require it)",
        required=True,
    )
    output_file = OptString("", "Optional JSON output file", required=False)
    store_results = OptBool(True, "Store DTCs in session.data['dtcs']", required=False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.DOIP.value:
            print_error(f"Session is not DoIP (type: {session.session_type})")
            return False
        if _parse_int(self.sub_function) is None:
            print_error(f"Invalid sub_function: {self.sub_function}")
            return False
        if _parse_int(self.status_mask) is None:
            print_error(f"Invalid status_mask: {self.status_mask}")
            return False
        try:
            self.open_doip()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_doip()
        target = _parse_int(self.target_address, None)
        if str(self.target_address or "").strip() and target is None:
            print_error(f"Invalid target address: {self.target_address}")
            return False
        if not target:
            target = self.resolve_target_address()

        sub = _parse_int(self.sub_function, UDS_DTC_REPORT_BY_STATUS_MASK) & 0xFF
        mask = _parse_int(self.status_mask, 0xFF) & 0xFF

        print_info("=" * 80)
        print_success("DoIP DTC Read")
        print_info(f"Target       : 0x{target:04X}")
        print_info(f"Sub-function : 0x{sub:02X}")
        print_info(f"Status mask  : 0x{mask:02X}")
        print_info("=" * 80)

        records, result = client.read_dtcs(
            status_mask=mask,
            target_address=target,
            sub_function=sub,
        )

        if not result.success:
            detail = result.nrc_name or result.raw_error or "UDS request failed"
            print_error(f"DTC read failed: {detail}")
            if result.response:
                print_info(f"Raw response: {result.response.hex()}")
            return False

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_address": target,
            "sub_function": sub,
            "status_mask": mask,
            "response_hex": result.response.hex() if result.response else "",
            "dtc_count": len(records),
            "dtcs": [
                {
                    "code": dtc.code,
                    "raw": dtc.raw,
                    "raw_hex": f"0x{dtc.raw:06X}",
                    "status": dtc.status,
                    "status_hex": dtc.status_hex,
                }
                for dtc in records
            ],
        }

        if not records:
            print_warning("No DTCs reported (empty list or none matching status mask)")
        else:
            print_success(f"Found {len(records)} DTC(s)")
            for dtc in records:
                print_info(f"  {dtc.code}  status={dtc.status_hex}")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["dtcs"] = report
                session.data = data

        out = str(self.output_file or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Wrote report to {out}")
            except OSError as exc:
                print_error(f"Failed to write output file: {exc}")

        return True
