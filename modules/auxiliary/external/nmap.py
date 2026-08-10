#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run nmap and persist hosts/services into the workspace DB (no XML file required)."""

from __future__ import annotations

from pathlib import Path

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "Nmap Workspace Integrator",
        "description": (
            "Run nmap (or import existing XML) and write structured hosts/ports/OS/"
            "service versions directly into the active workspace database. XML is "
            "captured from stdout via -oX - — no intermediate files needed."
        ),
        "author": ["KittySploit Team"],
        "tags": ["external", "nmap", "portscan", "discovery", "network", "integrator"],
        "references": [
            "https://nmap.org/book/man.html",
            "https://attack.mitre.org/techniques/T1046/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1046"],
            "prerequisites": [
                "nmap installed on the operator host",
                "Authorized network access to target host or CIDR",
            ],
            "detections": [
                "Network IDS alert for nmap/service fingerprinting",
                "Firewall flow logs for horizontal port sweeps",
            ],
            "artifacts": [
                "Firewall / Zeek / NetFlow records",
                "Workspace Host/Service rows (source=nmap)",
            ],
        },
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "cost": 1.2,
            "noise": 0.65,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "port_map", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    rhosts = OptString(
        "",
        "Target host, CIDR, or comma-separated list (ignored if xml_file is set)",
        required=False,
    )
    ports = OptString("", "Ports for -p (e.g. 22,80,443 or 1-1024). Empty = nmap default", required=False)
    arguments = OptString(
        "-sV",
        "Extra nmap args (do not set -oX/-oA — XML is forced to stdout)",
        required=False,
    )
    xml_file = OptString(
        "",
        "Optional path to an existing nmap XML file (skip live scan)",
        required=False,
    )
    timeout = OptInteger(600, "nmap process timeout (seconds)", required=False)
    open_only = OptBool(True, "Persist only open ports (recommended)", required=False)
    sync_workspace = OptBool(True, "Write results into the active workspace DB", required=False)

    def run(self):
        from lib.scanner.nmap import nmap_available, parse_nmap_xml, run_nmap

        xml_path = str(self.xml_file or "").strip()
        xml_text = ""

        if xml_path:
            path = Path(xml_path).expanduser()
            if not path.is_file():
                print_error(f"xml_file not found: {path}")
                return False
            print_status(f"Importing nmap XML: {path}")
            xml_text = path.read_text(encoding="utf-8", errors="replace")
        else:
            targets = str(self.rhosts or "").strip()
            if not targets:
                print_error("Set rhosts (or xml_file to import an offline scan)")
                return False

            avail = nmap_available()
            if not avail.get("available"):
                print_error("nmap not found on PATH")
                print_info(avail.get("install_hint") or "apt install nmap")
                return False

            print_status(
                f"Running nmap cli={avail.get('cli')} targets={targets!r} "
                f"ports={str(self.ports or '')!r} args={str(self.arguments or '')!r}"
            )
            result = run_nmap(
                targets,
                ports=str(self.ports or ""),
                arguments=str(self.arguments or "-sV"),
                timeout_sec=int(self.timeout or 600),
            )
            if result.get("cmd"):
                print_info("cmdline: " + " ".join(result["cmd"]))
            if result.get("stderr"):
                # Progress / warnings from nmap
                for line in str(result["stderr"]).splitlines()[-8:]:
                    print_info(line)
            if not result.get("ok"):
                print_error(result.get("error") or "nmap failed")
                return False
            xml_text = result.get("xml") or ""

        try:
            report = parse_nmap_xml(xml_text)
        except ValueError as exc:
            print_error(str(exc))
            return False

        hosts = report.get("hosts") or []
        if not hosts:
            print_warning("No hosts in nmap output")
            return False

        open_total = 0
        print_info("=" * 72)
        for host in hosts:
            address = host.get("address") or "?"
            hostname = host.get("hostname")
            label = f"{hostname} ({address})" if hostname else address
            os_name = host.get("os")
            services = host.get("services") or []
            open_svcs = [s for s in services if (s.get("state") or "") == "open"]
            open_total += len(open_svcs)
            if open_svcs:
                bits = []
                for s in sorted(open_svcs, key=lambda x: (x.get("protocol") or "", int(x.get("port") or 0))):
                    name = s.get("name") or "?"
                    ver = s.get("version")
                    entry = f"{s.get('port')}/{s.get('protocol')} {name}"
                    if ver:
                        entry += f" ({ver})"
                    bits.append(entry)
                print_success(f"{label}: {len(open_svcs)} open — {', '.join(bits)}")
            else:
                print_info(f"{label}: status={host.get('status')} (no open ports recorded)")
            if os_name:
                print_info(f"  OS: {os_name}")
        print_info("=" * 72)
        print_success(f"Parsed {len(hosts)} host(s), {open_total} open service(s)")

        if not bool(self.sync_workspace):
            print_info("sync_workspace=false — skipped DB write")
            return bool(hosts)

        saved = self._sync_workspace(report)
        if saved:
            print_info(
                f"Workspace updated: {saved.get('hosts', 0)} host(s), "
                f"{saved.get('services', 0)} service(s) — visible in Cosmic Network Map"
            )
        else:
            print_warning("Could not update workspace (is a workspace selected?)")
        return bool(hosts)

    def _sync_workspace(self, report) -> dict:
        if not getattr(self, "framework", None):
            return {}
        try:
            from core.workspace_intel import WorkspaceIntelStore

            return WorkspaceIntelStore(self.framework).record_nmap_scan(
                report,
                source="auxiliary/external/nmap",
                open_only=bool(self.open_only),
            )
        except Exception as exc:
            print_warning(f"Could not update workspace: {exc}")
            return {}
