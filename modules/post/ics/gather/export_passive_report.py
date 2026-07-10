#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import shutil

from kittysploit import *
from lib.protocols.ics.report import save_report


class Module(Post):
    __info__ = {
        "name": "Export passive ICS report",
        "description": (
            "Loads a JSON report produced by auxiliary/scanner/ics/passive_sniffer "
            "and optionally copies it or syncs discovered OT assets to the workspace."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "ot", "report", "passive", "gather"],
    'agent': {
        'risk': '',
        'effects': [],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    report_file = OptFile("", "Path to passive sniffer JSON report", True)
    output_file = OptString("", "Optional destination path for a report copy", False)
    sync_workspace = OptBool(True, "Sync OT assets from the report into the workspace", False)

    def check(self):
        path = str(self.report_file or "").strip()
        if not path or not os.path.isfile(path):
            print_error(f"Report file not found: {self.report_file}")
            return False
        try:
            with open(path, "r", encoding="utf-8") as handle:
                json.load(handle)
            return True
        except Exception as exc:
            print_error(f"Invalid JSON report: {exc}")
            return False

    def run(self):
        source = str(self.report_file).strip()
        with open(source, "r", encoding="utf-8") as handle:
            report = json.load(handle)

        summary = report.get("summary") or {}
        print_info(f"Report: {source}")
        print_info(f"  Devices: {summary.get('device_count', len(report.get('devices') or []))}")
        print_info(f"  Findings: {summary.get('finding_count', len(report.get('findings') or []))}")
        print_info(f"  Flows: {summary.get('flow_count', len(report.get('flows') or []))}")

        destination = str(self.output_file or "").strip()
        if destination:
            os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
            if destination.endswith(".json"):
                save_report(destination, report)
            else:
                shutil.copy2(source, destination)
            print_success(f"Report exported to {destination}")

        if bool(self.sync_workspace) and self.framework:
            try:
                from core.workspace_intel import WorkspaceIntelStore

                saved = WorkspaceIntelStore(self.framework).record_ics_passive_scan(report)
                print_success(f"Workspace updated: {saved} ICS service record(s) saved")
            except Exception as exc:
                print_warning(f"Could not sync workspace: {exc}")

        return True
