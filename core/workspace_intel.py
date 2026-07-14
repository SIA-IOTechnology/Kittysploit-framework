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
    ) -> int:
        """Persist all open ports from a {host: {port: state}} scan result."""
        saved = 0
        for host_address, ports in (results or {}).items():
            for port, state in (ports or {}).items():
                if state != "open":
                    continue
                if self.record_open_port(host_address, int(port), state="open", source=source):
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
