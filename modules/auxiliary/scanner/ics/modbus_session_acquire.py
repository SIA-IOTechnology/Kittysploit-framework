#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.modbus_client import ModbusTCPClient


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "Modbus session acquire",
        "description": (
            "Opens a Modbus TCP session and registers it in the framework session list "
            "for follow-on OT modules and the Modbus shell."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "modbus", "session", "scada"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints', 'risk_signals'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'modbus_tcp', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['post/ics/modbus/gather/map_registers',
                                 'post/ics/manage/modbus_write_register']},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["modbus-tcp"], "Modbus TCP port", True)
    unit_id = OptInteger(1, "Default Modbus unit ID", False)
    unit_start = OptInteger(1, "First unit ID to scan", False, advanced=True)
    unit_end = OptInteger(32, "Last unit ID to scan", False, advanced=True)
    create_session = OptBool(True, "Register a Modbus session on success", False)

    def _store_live_client(self, session_id: str, client: ModbusTCPClient) -> None:
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

        client = ModbusTCPClient(host, self._port(), self._timeout())
        if not client.connect():
            print_error(f"Modbus TCP connection failed for {host}:{self._port()}")
            return False

        units = client.scan_unit_ids(int(self.unit_start or 1), int(self.unit_end or 32))
        print_success(f"Modbus TCP session established with {host}:{self._port()}")
        if units:
            print_info(f"  Responsive units: {', '.join(str(item.unit_id) for item in units[:16])}")
        else:
            print_warning("Connected but no responsive unit IDs found in scan range")

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
            "unit_id": int(self.unit_id or 1),
            "protocol": "modbus-tcp",
            "platform": "ics",
            "units": [
                {"unit_id": item.unit_id, "registers": item.values[:8]}
                for item in units
            ],
        }
        session_id = self.framework.session_manager.create_session(
            host=host,
            port=int(self._port()),
            session_type=SessionType.MODBUS.value,
            data=session_data,
        )
        self._store_live_client(session_id, client)
        print_success(f"Modbus session registered: {session_id}")
        print_info("Use `sessions -i <id>` to open the Modbus shell")
        return ModuleResult(success=True, session_id=session_id, data=session_data)
