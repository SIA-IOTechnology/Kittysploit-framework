#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Serialize passive ICS analysis results for export and workspace sync."""

from __future__ import annotations

import html
import json
import time
from typing import Any


def _normalize_device(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": device.get("ip"),
        "mac": device.get("mac"),
        "vendor": device.get("vendor", "Unknown"),
        "device_type": device.get("device_type", "Unknown"),
        "purdue_level": device.get("purdue_level", 0),
        "protocols": sorted(device.get("protocols") or []),
        "roles": sorted(device.get("roles") or []),
        "peers": sorted(device.get("peers") or []),
        "packet_count": int(device.get("packet_count") or 0),
    }


def build_report(
    *,
    devices: dict[str, dict[str, Any]],
    flows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    packet_total: int,
    capture: dict[str, Any],
) -> dict[str, Any]:
    return {
        "module": "auxiliary/scanner/ics/passive_sniffer",
        "generated_at": time.time(),
        "capture": capture,
        "summary": {
            "packet_total": packet_total,
            "device_count": len(devices),
            "flow_count": len(flows),
            "finding_count": len(findings),
            "purdue_violation_count": sum(
                1 for item in findings if str(item.get("type", "")).startswith("purdue_")
            ),
        },
        "devices": [_normalize_device(devices[ip]) for ip in sorted(devices)],
        "flows": flows,
        "findings": findings,
    }


def build_engagement_report(
    passive_report: dict[str, Any] | None = None,
    *,
    title: str = "ICS Engagement Report",
    workspace_services: list[dict[str, Any]] | None = None,
    active_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    passive = passive_report or {}
    summary = dict(passive.get("summary") or {})
    devices = list(passive.get("devices") or [])
    flows = list(passive.get("flows") or [])
    findings = list(passive.get("findings") or [])
    if active_findings:
        findings.extend(active_findings)
        summary["finding_count"] = len(findings)
    protocols = sorted(
        {
            proto
            for device in devices
            for proto in (device.get("protocols") or [])
        }
    )
    purdue_violations = [
        item for item in findings if str(item.get("type", "")).startswith("purdue_")
    ]
    return {
        "title": title,
        "generated_at": time.time(),
        "summary": summary,
        "protocols": protocols,
        "devices": devices,
        "flows": flows,
        "findings": findings,
        "purdue_violations": purdue_violations,
        "workspace_services": workspace_services or [],
    }


def save_report(path: str, report: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)


def save_report_html(path: str, report: dict[str, Any]) -> None:
    title = html.escape(str(report.get("title") or "ICS Report"))
    summary = report.get("summary") or {}
    devices = report.get("devices") or []
    flows = report.get("flows") or []
    findings = report.get("findings") or []
    protocols = report.get("protocols") or []

    def row(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells) + "</tr>"

    device_rows = "".join(
        row(
            [
                device.get("ip", ""),
                device.get("vendor", ""),
                device.get("device_type", ""),
                f"L{device.get('purdue_level', 0)}",
                ", ".join(device.get("protocols") or []),
            ]
        )
        for device in devices
    ) or row(["", "No devices", "", "", ""])

    flow_rows = "".join(
        row(
            [
                flow.get("src", ""),
                flow.get("dst", ""),
                flow.get("port", ""),
                flow.get("protocol", ""),
                flow.get("packets", ""),
            ]
        )
        for flow in flows[:100]
    ) or row(["", "", "", "No flows", ""])

    finding_rows = "".join(
        row([item.get("severity", ""), item.get("type", ""), item.get("detail", "")])
        for item in findings[:100]
    ) or row(["", "No findings", ""])

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; color: #1f2937; }}
    h1, h2 {{ color: #0f766e; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }}
    th {{ background: #ecfeff; }}
    .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 1rem; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <div class="summary">
    <div class="card">Devices: {summary.get('device_count', len(devices))}</div>
    <div class="card">Flows: {summary.get('flow_count', len(flows))}</div>
    <div class="card">Findings: {summary.get('finding_count', len(findings))}</div>
    <div class="card">Purdue violations: {summary.get('purdue_violation_count', len([f for f in findings if str(f.get('type','')).startswith('purdue_')]))}</div>
  </div>
  <h2>Protocols</h2>
  <p>{html.escape(", ".join(protocols) or "n/a")}</p>
  <h2>Device inventory</h2>
  <table>
    <tr><th>IP</th><th>Vendor</th><th>Type</th><th>Purdue</th><th>Protocols</th></tr>
    {device_rows}
  </table>
  <h2>Flows (SCADA → PLC sample)</h2>
  <table>
    <tr><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Packets</th></tr>
    {flow_rows}
  </table>
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>Detail</th></tr>
    {finding_rows}
  </table>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
