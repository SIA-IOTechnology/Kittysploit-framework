#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Export command — write workspace data as JSON for KittySploit Reports import.
"""

import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning


class ExportCommand(BaseCommand):
    """Export hosts/vulnerabilities to a Reports-importable JSON bundle."""

    FORMAT_ID = "kittysploit.reports.import.v1"

    @property
    def name(self) -> str:
        return "export"

    @property
    def description(self) -> str:
        return "Export workspace data to JSON for KittySploit Reports import"

    @property
    def usage(self) -> str:
        return "export [-o|--output <file.json>] [--hosts-only] [--vulns-only]"

    @property
    def help_text(self) -> str:
        return """
Export the current workspace to a JSON file for manual import into
KittySploit Reports (when API push is unavailable or offline).

Options:
    -o, --output <file>   Output path (default: output/kittysploit-export-<workspace>-<ts>.json)
    --hosts-only          Export hosts (and services) only
    --vulns-only          Export vulnerabilities only

Examples:
    export
    export -o engagement.json
    export --hosts-only -o hosts.json
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Export workspace data to JSON for Reports import",
            add_help=True,
        )
        parser.add_argument(
            "-o", "--output",
            dest="output",
            help="Output JSON file path",
        )
        parser.add_argument(
            "--hosts-only",
            action="store_true",
            help="Export hosts and services only",
        )
        parser.add_argument(
            "--vulns-only",
            action="store_true",
            help="Export vulnerabilities only",
        )
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        if args and args[0].lower() in ("help", "--help", "-h"):
            self.parser.print_help()
            return True

        if parsed.hosts_only and parsed.vulns_only:
            print_error("Use only one of --hosts-only or --vulns-only")
            return False

        include_hosts = not parsed.vulns_only
        include_vulns = not parsed.hosts_only
        return self._export(parsed.output, include_hosts=include_hosts, include_vulns=include_vulns)

    def _get_db_session(self):
        if not hasattr(self.framework, "get_db_session"):
            return None
        return self.framework.get_db_session()

    def _current_workspace(self):
        if hasattr(self.framework, "workspace_manager"):
            return self.framework.workspace_manager.get_current_workspace()
        return None

    def _default_output_path(self, workspace_name: str) -> str:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in workspace_name) or "workspace"
        filename = f"kittysploit-export-{safe}-{ts}.json"
        out_dir = "output"
        os.makedirs(out_dir, mode=0o755, exist_ok=True)
        return os.path.join(out_dir, filename)

    def _severity(self, risk_level: Optional[str]) -> str:
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
            "unknown": "unknown",
        }
        return mapping.get((risk_level or "unknown").lower(), "unknown")

    def _host_to_target(self, host) -> Dict[str, Any]:
        address = host.address or ""
        hostname = host.hostname or None
        return {
            "schema_version": "1.0",
            "id": f"host-{host.id}",
            "type": "ip" if address and all(p.isdigit() for p in address.replace(".", " ").split()) else "host",
            "raw": hostname or address or f"host-{host.id}",
            "address": address or None,
            "hostname": hostname,
            "metadata": {
                "os": host.os,
                "os_version": host.os_version,
                "mac": host.mac,
                "status": host.status,
                "source_id": host.id,
            },
        }

    def _vuln_to_finding(self, vuln, host_ids: List[int]) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "id": f"vuln-{vuln.id}",
            "title": vuln.name or f"Vulnerability {vuln.id}",
            "description": vuln.description,
            "severity": self._severity(vuln.risk_level),
            "status": "open",
            "cve": vuln.cve,
            "cvss_score": vuln.cvss_score,
            "affected_targets": [f"host-{hid}" for hid in host_ids],
            "remediation": vuln.remediation,
            "evidence": (
                [{"schema_version": "1.0", "id": f"poc-vuln-{vuln.id}", "type": "text", "content": vuln.proof_of_concept}]
                if vuln.proof_of_concept
                else []
            ),
            "metadata": {
                "source_id": vuln.id,
                "risk_level": vuln.risk_level,
                "service_id": vuln.service_id,
                "proof_of_concept": vuln.proof_of_concept,
            },
        }

    def _export(
        self,
        output_path: Optional[str],
        include_hosts: bool = True,
        include_vulns: bool = True,
    ) -> bool:
        session = self._get_db_session()
        if not session:
            print_error("Database not available")
            return False

        workspace = self._current_workspace()
        if not workspace:
            print_error("No workspace found")
            return False

        try:
            from core.models.models import Host, Vulnerability, host_vulnerabilities

            hosts = (
                session.query(Host).filter(Host.workspace_id == workspace.id).all()
                if include_hosts or include_vulns
                else []
            )

            hosts_data: List[Dict[str, Any]] = []
            targets: List[Dict[str, Any]] = []
            if include_hosts:
                for host in hosts:
                    item = host.to_dict()
                    if hasattr(host, "services"):
                        item["services"] = [s.to_dict() for s in host.services]
                    else:
                        item["services"] = []
                    if hasattr(host, "vulnerabilities"):
                        item["vulnerability_ids"] = [v.id for v in host.vulnerabilities]
                    hosts_data.append(item)
                    targets.append(self._host_to_target(host))

            vulns_data: List[Dict[str, Any]] = []
            findings: List[Dict[str, Any]] = []
            if include_vulns:
                vulnerabilities = (
                    session.query(Vulnerability)
                    .join(host_vulnerabilities)
                    .join(Host)
                    .filter(Host.workspace_id == workspace.id)
                    .distinct()
                    .all()
                )
                for vuln in vulnerabilities:
                    item = vuln.to_dict()
                    linked_hosts = list(vuln.hosts) if hasattr(vuln, "hosts") else []
                    host_ids = [h.id for h in linked_hosts]
                    item["host_ids"] = host_ids
                    item["hosts"] = [
                        {"id": h.id, "address": h.address, "hostname": h.hostname}
                        for h in linked_hosts
                    ]
                    vulns_data.append(item)
                    findings.append(self._vuln_to_finding(vuln, host_ids))

            service_count = sum(len(h.get("services") or []) for h in hosts_data)
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

            bundle = {
                "schema_version": "1.0",
                "format": self.FORMAT_ID,
                "id": f"export-{uuid.uuid4().hex[:12]}",
                "workspace": workspace.name,
                "generated_at": now,
                "generated_by": "kittysploit-framework",
                "framework_version": getattr(self.framework, "version", None) or "1.0.0",
                "formats": ["json"],
                "hosts": hosts_data if include_hosts else [],
                "vulnerabilities": vulns_data if include_vulns else [],
                "targets": targets if include_hosts else [],
                "findings": findings if include_vulns else [],
                "summary": {
                    "host_count": len(hosts_data) if include_hosts else 0,
                    "service_count": service_count if include_hosts else 0,
                    "finding_count": len(findings) if include_vulns else 0,
                    "vulnerability_count": len(vulns_data) if include_vulns else 0,
                    "target_count": len(targets) if include_hosts else 0,
                },
            }

            path = output_path or self._default_output_path(workspace.name)
            parent = os.path.dirname(os.path.abspath(path))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, mode=0o755, exist_ok=True)

            with open(path, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=2, ensure_ascii=False)
                fh.write("\n")

            print_success(f"Exported to {path}")
            print_info(
                f"hosts={bundle['summary']['host_count']}  "
                f"services={bundle['summary']['service_count']}  "
                f"vulnerabilities={bundle['summary']['vulnerability_count']}"
            )
            print_info(f"format={self.FORMAT_ID}  (import manually in KittySploit Reports)")
            if bundle["summary"]["host_count"] == 0 and bundle["summary"]["vulnerability_count"] == 0:
                print_warning("Workspace has no hosts/vulnerabilities to export")
            return True

        except Exception as e:
            print_error(f"Export failed: {e}")
            import traceback
            traceback.print_exc()
            return False
