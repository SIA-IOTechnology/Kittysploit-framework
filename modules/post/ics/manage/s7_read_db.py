#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.ics_session_mixin import S7SessionMixin


class Module(Post, S7SessionMixin):
    __info__ = {
        "name": "S7 read DB",
        "description": "Reads bytes from a Siemens PLC data block via an active S7comm session",
        "author": "KittySploit Team",
        "session_type": SessionType.S7COMM,
        "tags": ["ics", "siemens", "s7comm", "gather"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["authenticated_session"],
                "produces_capabilities": ["file_read"],
            },
        },
    }

    db_number = OptInteger(1, "Data block number", True)
    start = OptInteger(0, "Byte offset inside the DB", True)
    size = OptInteger(16, "Number of bytes to read", True)

    def check(self):
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
        try:
            self.open_s7()
            return True
        except Exception as exc:
            print_error(f"S7comm connection error: {exc}")
            return False

    def run(self):
        client = self.open_s7()
        data = client.read_db(int(self.db_number), int(self.start), int(self.size))
        hex_dump = " ".join(f"{byte:02x}" for byte in data)
        print_success(
            f"DB{int(self.db_number)}@{int(self.start)} ({len(data)} bytes): {hex_dump}"
        )
        return True
