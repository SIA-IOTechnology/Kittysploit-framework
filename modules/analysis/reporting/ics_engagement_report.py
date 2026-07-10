#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os

from kittysploit import *
from lib.protocols.ics.report import build_engagement_report, save_report, save_report_html
from core.workspace_intel import ICS_SERVICE_NAMES


class Module(Analysis):
    __info__ = {
        "name": "ICS engagement report",
        "description": (
            "Builds a consolidated OT/ICS engagement report from passive JSON, workspace "
            "services, and optional active findings. Exports JSON and HTML."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "ot", "report", "purdue", "scada"],
    }

    passive_report = OptFile("", "Passive sniffer JSON report (optional)", False)
    output_json = OptString("ics_engagement_report.json", "Output JSON filename", False)
    output_html = OptString("ics_engagement_report.html", "Output HTML filename", False)
    title = OptString("ICS Engagement Report", "Report title", False)
    sync_workspace = OptBool(True, "Include ICS services from workspace intel", False)

    def _load_passive(self) -> dict:
        path = str(self.passive_report or "").strip()
        if not path or not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _workspace_services(self) -> list:
        if not bool(self.sync_workspace) or not self.framework:
            return []
        try:
            from core.models.models import Host, Service

            workspace_name = getattr(self.framework, "workspace", None) or "default"
            services = []
            with self.framework.db_manager.get_db_session(workspace_name) as session:
                hosts = session.query(Host).all()
                for host in hosts:
                    for service in getattr(host, "services", []) or []:
                        name = str(getattr(service, "name", "") or "").lower()
                        if name in ICS_SERVICE_NAMES.values() or any(
                            token in name for token in ("modbus", "s7", "bacnet", "dnp3", "iec104", "enip", "opcua", "ics")
                        ):
                            services.append(
                                {
                                    "host": getattr(host, "address", ""),
                                    "port": getattr(service, "port", ""),
                                    "name": getattr(service, "name", ""),
                                }
                            )
            return services
        except Exception as exc:
            print_warning(f"Could not load workspace ICS services: {exc}")
            return []

    def run(self):
        passive = self._load_passive()
        report = build_engagement_report(
            passive,
            title=str(self.title or "ICS Engagement Report"),
            workspace_services=self._workspace_services(),
        )
        out_dir = os.path.join(os.getcwd(), "output", "reports")
        os.makedirs(out_dir, exist_ok=True)

        json_name = str(self.output_json or "ics_engagement_report.json")
        html_name = str(self.output_html or "ics_engagement_report.html")
        json_path = json_name if os.path.isabs(json_name) else os.path.join(out_dir, json_name)
        html_path = html_name if os.path.isabs(html_name) else os.path.join(out_dir, html_name)

        save_report(json_path, report)
        save_report_html(html_path, report)
        print_success(f"JSON report saved to {json_path}")
        print_success(f"HTML report saved to {html_path}")

        summary = report.get("summary") or {}
        print_info(f"Devices: {summary.get('device_count', 0)}")
        print_info(f"Findings: {summary.get('finding_count', 0)}")
        print_info(f"Purdue violations: {summary.get('purdue_violation_count', 0)}")
        return True
