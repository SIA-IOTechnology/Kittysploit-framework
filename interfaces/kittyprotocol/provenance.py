#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os
import socket
import time
from typing import Any, Dict, Optional


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def analysis_actor() -> Dict[str, str]:
    return {
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "host": socket.gethostname(),
        "pid": str(os.getpid()),
    }


def build_provenance(
    source_path: Optional[str] = None,
    source_kind: str = "pcap",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    payload: Dict[str, Any] = {
        "generated_at": now,
        "source_kind": source_kind,
        "actor": analysis_actor(),
    }
    if source_path and os.path.isfile(source_path):
        try:
            payload["source_path"] = os.path.abspath(source_path)
            payload["source_sha256"] = sha256_file(source_path)
            payload["source_size_bytes"] = os.path.getsize(source_path)
        except OSError as exc:
            payload["source_error"] = str(exc)
    if extra:
        payload.update(extra)
    return payload
