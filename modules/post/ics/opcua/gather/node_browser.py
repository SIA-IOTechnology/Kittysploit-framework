#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.opcua_client import browse_opcua_nodes, opcua_available


class Module(Post, Ics_scanner_client):
    __info__ = {
        "name": "OPC UA node browser",
        "description": "Browses top-level OPC UA nodes via an OPC UA session or direct target",
        "author": "KittySploit Team",
        "session_type": SessionType.OPCUA,
        "tags": ["ics", "opcua", "gather", "browser"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints'],
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
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["opcua"], "OPC UA TCP port", True)
    ssl = OptBool(False, "Use TLS endpoint", False)
    max_nodes = OptInteger(30, "Maximum nodes to list", False)
    node_id = OptString("root", "NodeId to browse (root, objects, or ns=...;i=...)", False)

    def check(self):
        if self._session_data():
            return True
        return bool(self._host())

    def run(self):
        session_data = self._session_data()
        host = session_data.get("host") if session_data else self._host()
        port = int(session_data.get("port") or self._port()) if session_data else self._port()
        endpoint = str(session_data.get("endpoint") or "") if session_data else ""
        username = str(session_data.get("username") or "") if session_data else ""
        password = str(session_data.get("password") or "") if session_data else ""
        ssl = bool(session_data.get("ssl", bool(self.ssl))) if session_data else bool(self.ssl)
        if not host:
            print_error("Target is required")
            return False
        if not opcua_available():
            print_error("asyncua not installed — pip install asyncua")
            return False
        result = browse_opcua_nodes(
            host,
            port,
            ssl,
            int(self.max_nodes or 30),
            username=username,
            password=password,
            endpoint=endpoint,
            node_id=str(self.node_id or "root"),
        )
        if not result.connected:
            print_error(result.error or "OPC UA connection failed")
            return False
        print_success(f"OPC UA connected — {len(result.nodes)} node(s)")
        for node in result.nodes[: int(self.max_nodes or 30)]:
            print_info(f"  {node}")
        if not result.nodes:
            print_warning("Browse completed — no nodes returned")
        return True

    def _session_data(self):
        try:
            sid = str(self.session_id or "").strip()
            if not sid or not self.framework or not hasattr(self.framework, "session_manager"):
                return {}
            session = self.framework.session_manager.get_session(sid)
            if not session or str(session.session_type).lower() != "opcua":
                return {}
            return session.data or {}
        except Exception:
            return {}
