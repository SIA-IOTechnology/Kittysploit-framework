#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3
import tempfile
import uuid
from typing import Any, Dict, List, Optional


class PayloadIndex:
    """SQLite FTS5 index for payload/search text (per analysis run)."""

    def __init__(self) -> None:
        self._path: Optional[str] = None
        self._conn: Optional[sqlite3.Connection] = None

    def start(self) -> None:
        self.close()
        fd, path = tempfile.mkstemp(prefix="kp_", suffix=".sqlite")
        os.close(fd)
        self._path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("CREATE VIRTUAL TABLE payloads USING fts5(flow_id, pkt_no, body)")
        self._conn.commit()

    def add(self, flow_id: str, pkt_no: int, text: str) -> None:
        if not self._conn:
            return
        self._conn.execute(
            "INSERT INTO payloads(flow_id, pkt_no, body) VALUES (?,?,?)",
            (flow_id, int(pkt_no), str(text or "")[:8000]),
        )

    def commit(self) -> None:
        if self._conn:
            self._conn.commit()

    def search(self, query: str, limit: int = 80) -> List[Dict[str, Any]]:
        if not self._conn or not str(query or "").strip():
            return []
        try:
            cur = self._conn.execute(
                "SELECT flow_id, pkt_no, snippet(payloads, 2, '[', ']', '…', 32) AS snip FROM payloads WHERE payloads MATCH ? LIMIT ?",
                (query.strip(), int(limit)),
            )
            rows = []
            for flow_id, pkt_no, snip in cur.fetchall():
                rows.append({"flow_id": flow_id, "packet_number": pkt_no, "snippet": snip})
            return rows
        except sqlite3.OperationalError:
            return []

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        if self._path and os.path.isfile(self._path):
            try:
                os.remove(self._path)
            except OSError:
                pass
        self._path = None
