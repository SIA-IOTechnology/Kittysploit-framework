#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DoIP ECU Discovery - Probes logical addresses with UDS TesterPresent over DoIP
"""

from kittysploit import *
from lib.protocols.doip.constants import DOIP_FUNCTIONAL_ADDRESS
from lib.protocols.doip.doip_session_mixin import DoIPSessionMixin
import json
from datetime import datetime


def _parse_int(value, default=0):
    if value is None or value == "":
        return default
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


class Module(Post, DoIPSessionMixin):
    __info__ = {
        "name": "DoIP ECU Discovery",
        "description": (
            "Discovers responsive ECUs on a DoIP gateway by probing logical "
            "addresses with UDS TesterPresent (0x3E)"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.DOIP,
        "tags": ["automotive", "doip", "gather", "ecu", "uds"],
        "references": [
            "ISO 13400-2",
            "ISO 14229-1",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon", "network_probe"],
            "expected_requests": 16,
            "reversible": True,
            "approval_required": True,
            "produces": ["ot_assets"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.5,
            "chain": {
                "consumes_capabilities": ["doip_session"],
                "produces_capabilities": [
                    {"capability": "ot_assets", "from_detail": "ecu_map"},
                    {"capability": "doip_ecu_map", "from_detail": ""},
                ],
                "suggested_followups": [
                    "post/automotive/doip/gather/vin",
                    "post/automotive/doip/gather/dtc_read",
                    "post/automotive/doip/exploits/uds_query",
                ],
            },
        },
    }

    start_address = OptString("0x0001", "First logical address to probe", required=True)
    end_address = OptString("0x00FF", "Last logical address to probe", required=True)
    step = OptInteger(1, "Address step", required=True)
    include_functional = OptBool(True, "Also probe functional address 0xE400", required=True)
    include_entity = OptBool(True, "Also probe entity address from routing activation", required=True)
    output_file = OptString("", "Optional JSON output file", required=False)
    store_results = OptBool(True, "Store results in session.data['ecu_map']", required=False)

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
        start = _parse_int(self.start_address)
        end = _parse_int(self.end_address)
        if start is None or end is None:
            print_error("Invalid start/end address")
            return False
        if start > end:
            print_error("start_address must be <= end_address")
            return False
        try:
            self.open_doip()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_doip()
        start = _parse_int(self.start_address, 1)
        end = _parse_int(self.end_address, 0xFF)
        step = max(1, int(self.step or 1))

        print_info("=" * 80)
        print_success("DoIP ECU Discovery")
        print_info(f"Range      : 0x{start:04X}-0x{end:04X} step={step}")
        print_info(f"Host       : {client.host}:{client.port}")
        print_info(f"Tester     : 0x{client.source_address:04X}")
        if client.entity_address is not None:
            print_info(f"Entity     : 0x{client.entity_address:04X}")
        print_info("=" * 80)

        addresses = list(range(start & 0xFFFF, (end & 0xFFFF) + 1, step))
        if bool(self.include_entity) and client.entity_address and client.entity_address not in addresses:
            addresses.insert(0, client.entity_address)
        if bool(self.include_functional) and DOIP_FUNCTIONAL_ADDRESS not in addresses:
            addresses.append(DOIP_FUNCTIONAL_ADDRESS)

        ecus = []
        for addr in addresses:
            print_status(f"Probing 0x{addr:04X}...")
            probe = client.probe_ecu(addr)
            # Responsive positive response, or any NRC, means an ECU answered
            if probe.responsive or probe.nrc is not None:
                entry = {
                    "address": addr,
                    "address_hex": f"0x{addr:04X}",
                    "responsive": probe.responsive,
                    "nrc": probe.nrc,
                    "error": probe.error or "",
                    "response_hex": probe.response.hex() if probe.response else "",
                    "classification": (
                        "uds_functional"
                        if addr == DOIP_FUNCTIONAL_ADDRESS
                        else "uds_physical"
                    ),
                }
                ecus.append(entry)
                flag = "OK" if probe.responsive else f"NRC={probe.nrc:#04x}" if probe.nrc is not None else probe.error
                print_success(f"  ECU 0x{addr:04X} — {flag}")

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": client.host,
            "port": client.port,
            "range": {"start": start, "end": end, "step": step},
            "ecu_count": len(ecus),
            "ecus": ecus,
        }

        print_info("-" * 80)
        if not ecus:
            print_warning("No responsive ECUs found in range")
        else:
            print_success(f"Found {len(ecus)} responsive logical address(es)")
            for ecu in ecus:
                status = "positive" if ecu["responsive"] else f"nrc={ecu['nrc']}"
                print_info(f"  {ecu['address_hex']}  [{ecu['classification']}]  {status}")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["ecu_map"] = report
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
