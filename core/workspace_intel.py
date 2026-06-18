#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist recon and scan findings into the workspace database."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Well-known TCP ports → service name for workspace records.
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
        """Attach an open port to a host in the current workspace."""
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

            svc_name = name or TCP_SERVICE_NAMES.get(int(port), f"tcp-{port}")
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
