#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist recon and scan findings into the workspace database."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Well-known TCP ports → service name for workspace records.
ICS_SERVICE_NAMES: Dict[int, str] = {
    102: "s7comm",
    111: "sunrpc",
    502: "modbus-tcp",
    2404: "iec104",
    20000: "dnp3",
    44818: "enip",
    47808: "bacnet",
    4840: "opcua",
    8000: "qconn",
}

TCP_SERVICE_NAMES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http",
    8443: "https",
}


class WorkspaceIntelStore:
    """Write hosts, open ports, and light metadata into the active workspace."""

    def __init__(self, framework: Any):
        self.framework = framework

    def record_open_port(
        self,
        host_address: str,
        port: int,
        *,
        protocol: str = "tcp",
        name: Optional[str] = None,
        state: str = "open",
        source: str = "",
        hostname: Optional[str] = None,
    ) -> bool:
        if not host_address or not port:
            return False
        session = self._db_session()
        workspace_id = self._workspace_id()
        if not session or workspace_id is None:
            return False

        from core.models.models import Host, Service

        try:
            host = (
                session.query(Host)
                .filter(Host.workspace_id == workspace_id, Host.address == host_address)
                .first()
            )
            if not host:
                host = Host(
                    workspace_id=workspace_id,
                    address=host_address,
                    status="up",
                )
                session.add(host)
                session.flush()

            host.status = "up"
            host.updated_at = datetime.utcnow()
            # Keep DNS name when scanning via domain (don't overwrite with empty)
            if hostname and str(hostname).strip():
                hn = str(hostname).strip()
                if not host.hostname:
                    host.hostname = hn
                elif host.hostname.lower() != hn.lower() and host.address != hn:
                    # Prefer FQDN over short labels when longer
                    if len(hn) > len(host.hostname or ""):
                        host.hostname = hn

            svc_name = name or ICS_SERVICE_NAMES.get(int(port)) or TCP_SERVICE_NAMES.get(int(port), f"tcp-{port}")
            service = (
                session.query(Service)
                .filter(Service.port == int(port), Service.protocol == protocol)
                .first()
            )
            if not service:
                service = Service(
                    name=svc_name,
                    port=int(port),
                    protocol=protocol,
                    state=state,
                )
                session.add(service)
                session.flush()
            else:
                service.state = state
                if svc_name and (not service.name or service.name.startswith("tcp-")):
                    service.name = svc_name
                service.updated_at = datetime.utcnow()

            if service not in host.services:
                host.services.append(service)

            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            logger.warning("Could not record service %s:%s for %s (%s)", host_address, port, source, exc)
            return False

    def record_port_scan(
        self,
        results: Dict[str, Dict[int, str]],
        *,
        source: str = "portscan",
        hostnames: Optional[Dict[str, str]] = None,
    ) -> int:
        """Persist all open ports from a {host: {port: state}} scan result.

        hostnames: optional map {ip: original_domain} so Domain↔IP stays linked on the map.
        """
        saved = 0
        hostnames = hostnames or {}
        for host_address, ports in (results or {}).items():
            hostname = hostnames.get(host_address)
            for port, state in (ports or {}).items():
                if state != "open":
                    continue
                if self.record_open_port(
                    host_address,
                    int(port),
                    state="open",
                    source=source,
                    hostname=hostname,
                ):
                    saved += 1
        return saved

    def record_ics_passive_scan(
        self,
        report: Dict[str, Any],
        *,
        source: str = "auxiliary/scanner/ics/passive_sniffer",
    ) -> int:
        """Persist ICS endpoints and observed OT services into the workspace."""
        saved = 0
        devices = report.get("devices") or []
        if not devices:
            return 0

        session = self._db_session()
        workspace_id = self._workspace_id()
        if not session or workspace_id is None:
            return 0

        from core.models.models import Host

        try:
            for device in devices:
                host_address = device.get("ip")
                if not host_address:
                    continue

                host = (
                    session.query(Host)
                    .filter(Host.workspace_id == workspace_id, Host.address == host_address)
                    .first()
                )
                if not host:
                    host = Host(
                        workspace_id=workspace_id,
                        address=host_address,
                        status="up",
                    )
                    session.add(host)
                    session.flush()

                host.status = "up"
                host.updated_at = datetime.utcnow()

                mac = device.get("mac")
                if mac and not host.mac:
                    host.mac = mac

                device_type = device.get("device_type")
                if device_type and device_type != "Unknown":
                    host.os = device_type

                vendor = device.get("vendor")
                if vendor and vendor != "Unknown":
                    host.os_version = vendor

                for protocol in device.get("protocols") or []:
                    from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS

                    port = ICS_PROTOCOL_PORTS.get(protocol)
                    if not port:
                        continue

                    proto = "udp" if protocol == "bacnet" else "tcp"
                    if self.record_open_port(
                        host_address,
                        int(port),
                        protocol=proto,
                        name=protocol,
                        state="open",
                        source=source,
                    ):
                        saved += 1

            session.commit()
        except Exception as exc:
            session.rollback()
            logger.warning("Could not record ICS passive scan from %s (%s)", source, exc)
            return saved

        return saved

    def record_ics_asset(
        self,
        host_address: str,
        *,
        port: int | None = None,
        protocol: str = "",
        vendor: str = "",
        mac: str = "",
        device_type: str = "",
        purdue_level: int = 0,
        modbus_units: Optional[list] = None,
        s7_slot: Optional[int] = None,
        protection_level: Optional[int] = None,
        source: str = "",
    ) -> bool:
        """Persist OT asset metadata discovered during active ICS modules."""
        if not host_address:
            return False

        from lib.protocols.ics.ot_intel import build_ot_asset_record

        record = build_ot_asset_record(
            host_address,
            port=port,
            protocol=protocol,
            vendor=vendor,
            mac=mac,
            modbus_units=modbus_units,
            s7_slot=s7_slot,
            protection_level=protection_level,
            device_type=device_type,
        )
        if purdue_level:
            record["purdue_level"] = int(purdue_level)
        elif not record.get("purdue_level"):
            record["purdue_level"] = 0

        session = self._db_session()
        workspace_id = self._workspace_id()
        if not session or workspace_id is None:
            return False

        from core.models.models import Host, Note

        try:
            host = (
                session.query(Host)
                .filter(Host.workspace_id == workspace_id, Host.address == host_address)
                .first()
            )
            if not host:
                host = Host(
                    workspace_id=workspace_id,
                    address=host_address,
                    status="up",
                )
                session.add(host)
                session.flush()

            host.status = "up"
            host.updated_at = datetime.utcnow()
            if mac and not host.mac:
                host.mac = mac
            if record.get("device_type") and record["device_type"] != "Unknown":
                host.os = str(record["device_type"])
            if vendor or record.get("vendor"):
                host.os_version = str(vendor or record.get("vendor"))

            if port:
                proto = "udp" if str(protocol).lower() == "bacnet" else "tcp"
                self.record_open_port(
                    host_address,
                    int(port),
                    protocol=proto,
                    name=str(protocol or ICS_SERVICE_NAMES.get(int(port), f"tcp-{port}")),
                    state="open",
                    source=source,
                )

            summary_parts = []
            if record.get("purdue_level"):
                summary_parts.append(f"Purdue L{record['purdue_level']}")
            if record.get("modbus_units"):
                summary_parts.append(f"Modbus units={record['modbus_units']}")
            if record.get("s7_slot") is not None:
                summary_parts.append(f"S7 slot={record['s7_slot']}")
            if record.get("protection_level") is not None:
                summary_parts.append(f"S7 protection={record['protection_level']}")
            if protocol:
                summary_parts.append(f"protocol={protocol}")

            if summary_parts:
                note_text = f"OT intel ({source or 'ics'}): " + ", ".join(summary_parts)
                note = Note(
                    workspace_id=workspace_id,
                    host_id=host.id,
                    title="OT asset intel",
                    content=note_text,
                    category="recon",
                )
                session.add(note)

            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            logger.warning("Could not record ICS asset for %s (%s)", host_address, exc)
            return False

    def record_scanner_findings(
        self,
        findings: list,
        *,
        source: str = "scanner",
    ) -> Dict[str, int]:
        """
        Persist vulnerable scanner findings into the active workspace.

        Creates/updates Host + Service, then Vulnerability rows linked to both.
        Severity ``info`` is stored as ``low`` (DB constraint has no ``info``).
        """
        stats = {"saved": 0, "updated": 0, "skipped": 0, "failed": 0, "evidence": 0}
        if not findings:
            return stats

        session = self._db_session()
        workspace_id = self._workspace_id()
        if not session or workspace_id is None:
            logger.warning("Cannot persist scanner findings: no workspace DB session")
            return stats

        from core.models.models import Host, Service, Vulnerability

        for raw in findings:
            if not isinstance(raw, dict):
                stats["skipped"] += 1
                continue
            # Accept both table entries and raw vulnerable result dicts
            if raw.get("vulnerable") is False:
                stats["skipped"] += 1
                continue

            host_address = str(
                raw.get("host") or raw.get("hostname") or raw.get("address") or ""
            ).strip()
            if not host_address:
                stats["skipped"] += 1
                continue

            title = str(
                raw.get("title")
                or raw.get("finding")
                or raw.get("module")
                or raw.get("name")
                or "Scanner finding"
            ).strip()
            title = title.lstrip("[+]").strip() or "Scanner finding"

            severity = self._normalize_risk_level(raw.get("severity") or raw.get("risk_level"))
            cve = self._normalize_cve(raw.get("cve"))
            evidence = str(raw.get("evidence") or raw.get("message") or "").strip()
            module_path = str(
                raw.get("module_path")
                or raw.get("scanner_path")
                or raw.get("path")
                or ""
            ).strip()
            service_label = str(raw.get("service") or "").strip()
            port = raw.get("port")
            if port is None and ":" in service_label:
                try:
                    port = int(service_label.rsplit(":", 1)[-1])
                except ValueError:
                    port = None
            try:
                port_i = int(port) if port is not None else None
            except (TypeError, ValueError):
                port_i = None

            scheme = str(raw.get("scheme") or "").lower()
            svc_name = None
            if service_label and ":" in service_label:
                svc_name = service_label.split(":", 1)[0].strip() or None
            if not svc_name and scheme in ("http", "https"):
                svc_name = scheme
            if not svc_name and port_i:
                svc_name = TCP_SERVICE_NAMES.get(port_i, f"tcp-{port_i}")

            evidence_paths = [
                str(p).strip()
                for p in (raw.get("evidence_paths") or [])
                if str(p or "").strip()
            ]
            schema_evidence = [
                item
                for item in (raw.get("schema_evidence") or [])
                if isinstance(item, dict)
            ]

            structured = None
            try:
                from core.scanner.finding_report import (
                    extract_finding_report,
                    report_to_vulnerability_fields,
                )

                structured = extract_finding_report(raw)
            except Exception:
                structured = None

            rem_text = ""
            if structured:
                mapped = report_to_vulnerability_fields(structured)
                title = mapped["name"]
                severity = mapped["risk_level"]
                description = mapped["description"] or title
                rem_text = mapped.get("remediation") or ""
                proof = mapped.get("proof_of_concept") or ""
                if evidence_paths:
                    proof = (proof + "\nEvidence files:\n" + "\n".join(f"  - {p}" for p in evidence_paths[:8]))[:8000]
            else:
                poc_parts = []
                if evidence:
                    poc_parts.append(f"Evidence: {evidence}")
                if module_path:
                    poc_parts.append(f"Module: {module_path}")
                if service_label:
                    poc_parts.append(f"Service: {service_label}")
                if source:
                    poc_parts.append(f"Source: {source}")
                if evidence_paths:
                    poc_parts.append("Evidence files:")
                    for path in evidence_paths[:8]:
                        poc_parts.append(f"  - {path}")
                if schema_evidence:
                    try:
                        import json

                        preview = json.dumps(schema_evidence[:2], ensure_ascii=False, default=str)
                        poc_parts.append(f"Evidence JSON: {preview[:1500]}")
                    except Exception:
                        pass
                proof = "\n".join(poc_parts)

                description = evidence or title
                if module_path and module_path not in description:
                    description = f"{description}\nDetected by {module_path}".strip()

            try:
                host = (
                    session.query(Host)
                    .filter(Host.workspace_id == workspace_id, Host.address == host_address)
                    .first()
                )
                if not host:
                    host = Host(
                        workspace_id=workspace_id,
                        address=host_address,
                        hostname=host_address if not self._looks_like_ip(host_address) else None,
                        status="up",
                    )
                    session.add(host)
                    session.flush()
                else:
                    host.status = "up"
                    host.updated_at = datetime.utcnow()
                    if not host.hostname and not self._looks_like_ip(host_address):
                        host.hostname = host_address

                service = None
                if port_i:
                    service = (
                        session.query(Service)
                        .filter(Service.port == port_i, Service.protocol == "tcp")
                        .first()
                    )
                    if not service:
                        service = Service(
                            name=svc_name or f"tcp-{port_i}",
                            port=port_i,
                            protocol="tcp",
                            state="open",
                        )
                        session.add(service)
                        session.flush()
                    else:
                        service.state = "open"
                        if svc_name and (not service.name or str(service.name).startswith("tcp-")):
                            service.name = svc_name
                        service.updated_at = datetime.utcnow()
                    if service not in host.services:
                        host.services.append(service)

                # Dedup: same host + name + cve (+ service when present)
                q = (
                    session.query(Vulnerability)
                    .join(Vulnerability.hosts)
                    .filter(
                        Host.id == host.id,
                        Vulnerability.name == title[:255],
                    )
                )
                if cve:
                    q = q.filter(Vulnerability.cve == cve)
                else:
                    q = q.filter((Vulnerability.cve.is_(None)) | (Vulnerability.cve == ""))
                if service is not None:
                    q = q.filter(Vulnerability.service_id == service.id)
                existing = q.first()

                if existing:
                    existing.risk_level = severity
                    existing.description = description[:4000] if description else existing.description
                    if proof:
                        existing.proof_of_concept = proof[:8000]
                    if rem_text:
                        existing.remediation = rem_text[:4000]
                    if service is not None:
                        existing.service_id = service.id
                    existing.updated_at = datetime.utcnow()
                    if host not in existing.hosts:
                        existing.hosts.append(host)
                    stats["updated"] += 1
                else:
                    vuln = Vulnerability(
                        name=title[:255],
                        description=(description or "")[:4000],
                        cve=cve or None,
                        risk_level=severity,
                        proof_of_concept=(proof or "")[:8000],
                        remediation=(rem_text or "")[:4000],
                        service_id=service.id if service is not None else None,
                    )
                    session.add(vuln)
                    session.flush()
                    vuln.hosts.append(host)
                    stats["saved"] += 1

                # Prefer full structured report as loot when available
                loot_schema = schema_evidence
                if structured and not loot_schema:
                    loot_schema = [structured]
                loot_saved = self._persist_evidence_loot(
                    session,
                    workspace_id=workspace_id,
                    host=host,
                    title=title,
                    evidence_paths=evidence_paths,
                    schema_evidence=loot_schema,
                )
                stats["evidence"] = int(stats.get("evidence") or 0) + loot_saved

                session.commit()
            except Exception as exc:
                session.rollback()
                stats["failed"] += 1
                logger.warning(
                    "Could not persist scanner finding %r on %s (%s)",
                    title,
                    host_address,
                    exc,
                )

        return stats

    def _persist_evidence_loot(
        self,
        session,
        *,
        workspace_id: int,
        host,
        title: str,
        evidence_paths: list,
        schema_evidence: list,
    ) -> int:
        """Store evidence JSON as Loot rows linked to the host. Returns count saved."""
        import json
        import os

        from core.models.models import Loot

        saved = 0
        paths = list(evidence_paths or [])
        if not paths and schema_evidence:
            # Inline fallback when files were not written (still keep a loot row)
            try:
                content = json.dumps(schema_evidence, ensure_ascii=False, default=str)
            except Exception:
                content = str(schema_evidence)
            name = f"evidence:{title}"[:255]
            existing = (
                session.query(Loot)
                .filter(
                    Loot.workspace_id == workspace_id,
                    Loot.host_id == host.id,
                    Loot.name == name,
                    Loot.loot_type == "evidence",
                )
                .first()
            )
            if existing:
                existing.content = content[:50000]
                existing.file_size = len(content.encode("utf-8", errors="replace"))
            else:
                session.add(
                    Loot(
                        workspace_id=workspace_id,
                        host_id=host.id,
                        name=name,
                        loot_type="evidence",
                        content=content[:50000],
                        file_path=None,
                        file_size=len(content.encode("utf-8", errors="replace")),
                    )
                )
                saved += 1
            return saved

        for path in paths:
            abs_path = path
            if not os.path.isabs(abs_path):
                abs_path = os.path.join(os.getcwd(), path)
            content = ""
            size = 0
            is_binary = str(path).lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif"))
            try:
                if os.path.isfile(abs_path):
                    size = int(os.path.getsize(abs_path))
                    if is_binary:
                        content = json.dumps(
                            {
                                "kind": "screenshot",
                                "file_path": path,
                                "file_size": size,
                                "content_type": "image/png"
                                if str(path).lower().endswith(".png")
                                else "image/*",
                            },
                            ensure_ascii=False,
                        )
                    else:
                        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
                            content = handle.read(50000)
            except Exception:
                content = ""
            if not content and schema_evidence:
                try:
                    content = json.dumps(schema_evidence, ensure_ascii=False, default=str)[:50000]
                    size = len(content.encode("utf-8", errors="replace"))
                except Exception:
                    pass

            base = os.path.basename(path) or "evidence.json"
            loot_type = "screenshot" if is_binary else "evidence"
            name = f"{loot_type}:{base}"[:255]
            existing = (
                session.query(Loot)
                .filter(
                    Loot.workspace_id == workspace_id,
                    Loot.host_id == host.id,
                    Loot.file_path == path,
                    Loot.loot_type == loot_type,
                )
                .first()
            )
            if existing:
                existing.content = content or existing.content
                existing.file_size = size or existing.file_size
                existing.name = name
                continue

            session.add(
                Loot(
                    workspace_id=workspace_id,
                    host_id=host.id,
                    name=name,
                    loot_type=loot_type,
                    content=content or None,
                    file_path=path,
                    file_size=size or None,
                )
            )
            saved += 1
        return saved

    @staticmethod
    def _normalize_risk_level(value: Any) -> str:
        sev = str(value or "").strip().lower()
        if sev in ("critical", "crit"):
            return "critical"
        if sev == "high":
            return "high"
        if sev in ("medium", "moderate"):
            return "medium"
        if sev == "low":
            return "low"
        # DB check constraint has no "info" — map informational findings to low
        if sev in ("info", "informational"):
            return "low"
        return "unknown"

    @staticmethod
    def _normalize_cve(value: Any) -> Optional[str]:
        cve = str(value or "").strip().upper()
        if not cve:
            return None
        import re

        if re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            return cve
        return None

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        import re

        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value or ""))

    def _db_session(self):
        db = getattr(self.framework, "db_manager", None)
        if not db:
            return None
        return db.get_session("default")

    def _workspace_id(self) -> Optional[int]:
        wm = getattr(self.framework, "workspace_manager", None)
        if not wm:
            return None
        current = wm.get_current_workspace()
        return current.id if current else None
