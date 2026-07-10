#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.ics_session_mixin import ModbusSessionMixin


class Module(Post, ModbusSessionMixin):
    __info__ = {
        "name": "Modbus write coil",
        "description": "Writes a single Modbus coil (FC5) via an active Modbus session",
        "author": "KittySploit Team",
        "session_type": SessionType.MODBUS,
        "tags": ["ics", "modbus", "write", "coil"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    unit_id = OptInteger(0, "Modbus unit ID (0 = session default)", False)
    address = OptInteger(0, "Coil address", True)
    value = OptBool(True, "Coil value (ON/OFF)", True)
    dry_run = OptBool(False, "Validate only — do not write", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid or not self.framework.session_manager.get_session(sid):
            print_error("Valid Modbus session required")
            return False
        try:
            self.open_modbus()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def _unit(self) -> int:
        configured = int(self.unit_id or 0)
        if configured > 0:
            return configured
        return int(self.get_modbus_connection_info().get("unit_id") or 1)

    def run(self):
        client = self.open_modbus()
        unit = self._unit()
        address = int(self.address)
        state = bool(self.value)
        if bool(self.dry_run):
            before = client.read_coils(unit, address, 1)
            current = before.values[0] if before.success and before.values else "n/a"
            print_success(f"Dry run — coil {address} current={current}, would set {int(state)}")
            return True
        print_warning(f"Writing coil {address} = {state} on unit {unit}")
        result = client.write_single_coil(unit, address, state)
        if not result.success:
            print_error(result.raw_error or "Write rejected")
            return False
        print_success(f"Coil {address} write accepted")
        return True
