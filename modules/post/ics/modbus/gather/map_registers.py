#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.ics_session_mixin import ModbusSessionMixin


class Module(Post, ModbusSessionMixin):
    __info__ = {
        "name": "Modbus map registers",
        "description": "Maps Modbus holding/input registers or coils/discrete inputs via an active session",
        "author": "KittySploit Team",
        "session_type": SessionType.MODBUS,
        "tags": ["ics", "modbus", "gather", "registers"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    unit_id = OptInteger(0, "Modbus unit ID (0 = session default)", False)
    start = OptInteger(0, "Start address", True)
    count = OptInteger(16, "Number of points to read", True)
    register_type = OptString("holding", "holding, input, coil, or discrete", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid or not self.framework.session_manager.get_session(sid):
            print_error("Valid Modbus session required")
            return False
        if str(session.session_type).lower() != SessionType.MODBUS.value:
            print_error(f"Session is not Modbus (type: {session.session_type})")
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
        mapping = client.map_registers(
            self._unit(),
            int(self.start),
            int(self.count),
            str(self.register_type or "holding"),
        )
        if not mapping.get("success"):
            print_error(mapping.get("raw_error") or "Read failed")
            return False
        print_success(
            f"{mapping.get('type')} {mapping.get('start')}-{int(mapping.get('start', 0)) + len(mapping.get('values', [])) - 1}: "
            f"{mapping.get('values')}"
        )
        return True
