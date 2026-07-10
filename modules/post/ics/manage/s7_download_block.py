#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.ics.ics_session_mixin import S7SessionMixin
from lib.protocols.ics.s7_client import snap7_available


class Module(Post, S7SessionMixin):
    __info__ = {
        "name": "S7 download block",
        "description": (
            "Downloads an MC7 block (OB/FB/FC/DB/SDB) from a Siemens PLC via an active "
            "S7comm session. Requires python-snap7."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.S7COMM,
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "s7comm", "download", "mc7", "block"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': ['ot_assets', 'modbus_tcp', 's7comm', 'dnp3_access'],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    session_id = OptString("", "S7comm session ID", True)
    block_type = OptString("DB", "Block type (OB, FB, FC, DB, SDB, SFB, SFC)", True)
    block_number = OptInteger(1, "Block number", True)
    output_file = OptString("", "Local path to save the downloaded block", True)

    def check(self):
        if not snap7_available():
            print_error("python-snap7 is required for block download")
            return False
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error(f"Session {sid} not found")
            return False
        if str(session.session_type).lower() != SessionType.S7COMM.value:
            print_error(f"Session is not S7comm (type: {session.session_type})")
            return False
        if not str(self.output_file or "").strip():
            print_error("output_file is required")
            return False
        try:
            self.open_s7()
            return True
        except Exception as exc:
            print_error(f"S7comm connection error: {exc}")
            return False

    def run(self):
        client = self.open_s7()
        block_type = str(self.block_type or "DB").upper()
        block_number = int(self.block_number or 1)
        output_path = str(self.output_file).strip()

        print_status(f"Downloading {block_type}{block_number} from PLC...")
        data = client.download_block(block_type, block_number)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as handle:
            handle.write(data)
        print_success(f"Saved {len(data)} byte(s) to {output_path}")
        return True
