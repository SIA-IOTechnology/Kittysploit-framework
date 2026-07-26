#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DoIP VIN Gather - Reads vehicle VIN via UDS ReadDataByIdentifier (0x22 / DID 0xF190)
"""

from kittysploit import *
from lib.protocols.doip.constants import UDS_DID_VIN
from lib.protocols.doip.doip_session_mixin import DoIPSessionMixin


def _parse_address(value, default=0):
    if value is None or value == "":
        return default
    text = str(value).strip().lower()
    if not text:
        return default
    try:
        return int(text, 0) & 0xFFFF
    except ValueError:
        return None


class Module(Post, DoIPSessionMixin):
    __info__ = {
        "name": "DoIP Read VIN",
        "description": "Reads the vehicle VIN over DoIP using UDS ReadDataByIdentifier (DID 0xF190)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.DOIP,
        "tags": ["automotive", "doip", "gather", "vin", "uds"],
        "references": [
            "ISO 14229-1",
            "ISO 13400-2",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["vehicle_identity"],
            "cost": 0.5,
            "noise": 0.1,
            "value": 1.4,
            "chain": {
                "consumes_capabilities": ["doip_session"],
                "produces_capabilities": [
                    {"capability": "vehicle_identity", "from_detail": "vin"},
                ],
                "suggested_followups": [
                    "post/automotive/doip/gather/ecu_discovery",
                    "post/automotive/doip/gather/dtc_read",
                ],
            },
        },
    }

    target_address = OptString(
        "",
        "ECU logical address (hex, e.g. 0x0001). Empty = session default",
        required=False,
    )
    did = OptString("0xF190", "Data identifier to read (default VIN 0xF190)", required=False)
    store_results = OptBool(True, "Store VIN in session.data['vin']", required=False)

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
        try:
            self.open_doip()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_doip()
        target = _parse_address(self.target_address, None)
        if self.target_address and target is None:
            print_error(f"Invalid target address: {self.target_address}")
            return False
        if target is None or target == 0:
            target = self.resolve_target_address()

        did = _parse_address(self.did, UDS_DID_VIN)
        if did is None:
            print_error(f"Invalid DID: {self.did}")
            return False

        print_status(f"Reading DID 0x{did:04X} from ECU 0x{target:04X}...")

        if did == UDS_DID_VIN:
            vin, result = client.read_vin(target_address=target)
        else:
            result = client.read_data_by_identifier(did, target_address=target)
            vin = result.data.decode("ascii", errors="ignore").strip("\x00 ").strip() if result.success else None

        if not result.success:
            detail = result.nrc_name or result.raw_error or "UDS request failed"
            print_error(f"VIN/DID read failed: {detail}")
            if result.response:
                print_info(f"Raw response: {result.response.hex()}")
            return False

        if not vin:
            print_warning("Positive response but empty VIN/data")
            print_info(f"Raw data: {result.data.hex() if result.data else ''}")
            return False

        print_success(f"VIN: {vin}")
        print_info(f"Target ECU : 0x{target:04X}")
        print_info(f"DID        : 0x{did:04X}")
        print_info(f"Raw        : {result.response.hex()}")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["vin"] = vin
                data["vin_did"] = did
                data["vin_target"] = target
                session.data = data

        return True
