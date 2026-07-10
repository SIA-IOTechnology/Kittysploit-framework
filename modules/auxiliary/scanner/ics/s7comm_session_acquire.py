#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import S7Client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "S7comm session acquire",
        "description": (
            "Opens an authenticated S7comm session to a Siemens PLC and registers it "
            "in the framework session list for follow-on OT modules."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "siemens", "s7comm", "session", "scada"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["credentials"],
                "produces_capabilities": ["authenticated_session"],
                "suggested_followups": ["post/ics/manage/s7_read_db"],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)
    create_session = OptBool(True, "Register an S7comm session on success", False)

    def _store_live_client(self, session_id: str, client: S7Client) -> None:
        if not self.framework:
            return
        registry = getattr(self.framework, "_ics_session_clients", None)
        if registry is None:
            self.framework._ics_session_clients = {}
            registry = self.framework._ics_session_clients
        registry[session_id] = client

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        client = S7Client(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
        )
        if not client.connect():
            print_error(f"S7comm authentication/connection failed for {host}:{self._port()}")
            return False

        identity = client.identify()
        print_success(f"S7comm session established with {host}:{self._port()}")
        print_info(f"  Module: {identity.module_type_name or 'unknown'}")
        print_info(f"  Protection: {identity.protection_label}")

        if not bool(self.create_session):
            client.close()
            return True

        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_warning("Framework session manager unavailable — connection not registered")
            client.close()
            return True

        session_data = {
            "host": host,
            "port": self._port(),
            "rack": int(self.rack or 0),
            "slot": int(self.slot or 1),
            "password": str(self.password or ""),
            "protocol": "s7comm",
            "platform": "ics",
            "module_type_name": identity.module_type_name,
            "serial_number": identity.serial_number,
            "protection_level": identity.protection_level,
            "protection_label": identity.protection_label,
            "backend": identity.backend,
        }
        session_id = self.framework.session_manager.create_session(
            host=host,
            port=int(self._port()),
            session_type=SessionType.S7COMM.value,
            data=session_data,
        )
        self._store_live_client(session_id, client)
        print_success(f"S7comm session registered: {session_id}")
        print_info("Use `sessions -i <id>` to open the S7comm shell")
        return ModuleResult(success=True, session_id=session_id, data=session_data)
