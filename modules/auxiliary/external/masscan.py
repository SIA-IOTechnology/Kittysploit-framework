#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run masscan and persist open ports into the workspace DB (no JSON file required)."""

from __future__ import annotations

from pathlib import Path

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "Masscan Workspace Integrator",
        "description": (
            "Run masscan (or import existing -oJ JSON) and write open hosts/ports "
            "directly into the active workspace database. JSON is captured from "
            "stdout via -oJ - — no intermediate files needed. Pair with "
            "auxiliary/external/nmap for service/version enrichment."
        ),
        "author": ["KittySploit Team"],
        "tags": ["external", "masscan", "portscan", "discovery", "network", "integrator"],
        "references": [
            "https://github.com/robertdavidgraham/masscan",
            "https://attack.mitre.org/techniques/T1046/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1046"],
            "prerequisites": [
                "masscan installed on the operator host",
                "Raw socket privileges (root/CAP_NET_RAW) for SYN scans",
                "Authorized network access to target host or CIDR",
            ],
            "detections": [
                "Network IDS alert for high-rate SYN sweeps",
                "Firewall flow logs for horizontal port sweeps",
            ],
            "artifacts": [
                "Firewall / Zeek / NetFlow records",
                "Workspace Host/Service rows (source=masscan)",
            ],
        },
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.85,
            "value": 0.95,
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
                "suggested_followups": ["auxiliary/external/nmap"],
            },
        },
    }

    rhosts = OptString(
        "",
        "Target host, CIDR, or comma-separated list (ignored if json_file is set)",
        required=False,
    )
    ports = OptString("1-1024", "Ports for -p (e.g. 80,443 or 1-65535)", required=False)
    rate = OptInteger(1000, "Packets/sec (--rate). Keep low on constrained networks", required=False)
    arguments = OptString(
        "",
        "Extra masscan args (do not set -oJ/-oX/-p/--rate — handled by the module)",
        required=False,
    )
    json_file = OptString(
        "",
        "Optional path to an existing masscan -oJ file (skip live scan)",
        required=False,
    )
    timeout = OptInteger(600, "masscan process timeout (seconds)", required=False)
    open_only = OptBool(True, "Persist only open ports (recommended)", required=False)
    sync_workspace = OptBool(True, "Write results into the active workspace DB", required=False)

    def run(self):
        from lib.scanner.masscan import masscan_available, parse_masscan_json, run_masscan

        json_path = str(self.json_file or "").strip()
        json_text = ""

        if json_path:
            path = Path(json_path).expanduser()
            if not path.is_file():
                print_error(f"json_file not found: {path}")
                return False
            print_status(f"Importing masscan JSON: {path}")
            json_text = path.read_text(encoding="utf-8", errors="replace")
        else:
            targets = str(self.rhosts or "").strip()
            if not targets:
                print_error("Set rhosts (or json_file to import an offline scan)")
                return False

            avail = masscan_available()
            if not avail.get("available"):
                print_error("masscan not found on PATH")
                print_info(avail.get("install_hint") or "apt install masscan")
                return False

            ports = str(self.ports or "1-1024").strip() or "1-1024"
            rate = int(self.rate or 1000)
            print_status(
                f"Running masscan cli={avail.get('cli')} targets={targets!r} "
                f"ports={ports!r} rate={rate}"
            )
            print_info("Note: masscan typically needs root/CAP_NET_RAW for SYN scans")
            result = run_masscan(
                targets,
                ports=ports,
                rate=rate,
                arguments=str(self.arguments or ""),
                timeout_sec=int(self.timeout or 600),
            )
            if result.get("cmd"):
                print_info("cmdline: " + " ".join(result["cmd"]))
            if result.get("stderr"):
                for line in str(result["stderr"]).splitlines()[-10:]:
                    print_info(line)
            if not result.get("ok"):
                print_error(result.get("error") or "masscan failed")
                return False
            json_text = result.get("json") or ""

        report = parse_masscan_json(json_text)
        hosts = report.get("hosts") or []
        if not hosts:
            print_warning("No hosts/ports in masscan output")
            return False

        open_total = 0
        print_info("=" * 72)
        for host in hosts:
            address = host.get("address") or "?"
            services = host.get("services") or []
            open_svcs = [s for s in services if (s.get("state") or "") == "open"]
            open_total += len(open_svcs)
            if open_svcs:
                bits = [
                    f"{s.get('port')}/{s.get('protocol')}"
                    for s in sorted(
                        open_svcs,
                        key=lambda x: (x.get("protocol") or "", int(x.get("port") or 0)),
                    )
                ]
                print_success(f"{address}: {len(open_svcs)} open — {', '.join(bits)}")
            else:
                print_info(f"{address}: no open ports recorded")
        print_info("=" * 72)
        print_success(f"Parsed {len(hosts)} host(s), {open_total} open port(s)")

        if not bool(self.sync_workspace):
            print_info("sync_workspace=false — skipped DB write")
            return bool(hosts)

        saved = self._sync_workspace(report)
        if saved:
            print_info(
                f"Workspace updated: {saved.get('hosts', 0)} host(s), "
                f"{saved.get('services', 0)} service(s) — enrich with "
                f"auxiliary/external/nmap -sV if needed"
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
                source="auxiliary/external/masscan",
                open_only=bool(self.open_only),
            )
        except Exception as exc:
            print_warning(f"Could not update workspace: {exc}")
            return {}
