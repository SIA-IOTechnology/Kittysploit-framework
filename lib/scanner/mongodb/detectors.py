#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MongoDB detection helpers for scanner modules."""

from __future__ import annotations

from typing import Dict, List

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


def probe_mongodb(
    host: str,
    port: int = 27017,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """Detect MongoDB and whether unauthenticated access is possible."""
    result: Dict[str, object] = {
        "success": False,
        "host": host,
        "port": port,
        "detected": False,
        "unauthenticated": False,
        "auth_required": False,
        "version": "",
        "databases": [],
        "error": "",
    }
    if not PYMONGO_AVAILABLE:
        result["error"] = "pymongo not installed"
        return result

    timeout_ms = max(1000, int(timeout * 1000))
    uri = f"mongodb://{host}:{int(port)}/?directConnection=true&serverSelectionTimeoutMS={timeout_ms}"
    client = MongoClient(uri, connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms)
    try:
        info = client.server_info()
        result["success"] = True
        result["detected"] = True
        result["version"] = str(info.get("version", ""))
        try:
            databases = client.list_database_names()
            result["unauthenticated"] = True
            result["databases"] = databases[:20]
        except OperationFailure as exc:
            message = str(exc).lower()
            result["auth_required"] = True
            if "auth" in message or getattr(exc, "code", None) in (13, 18):
                result["success"] = True
            else:
                result["error"] = str(exc)
    except ServerSelectionTimeoutError as exc:
        result["error"] = str(exc)
    except OperationFailure as exc:
        message = str(exc).lower()
        if "auth" in message or getattr(exc, "code", None) in (13, 18):
            result["success"] = True
            result["detected"] = True
            result["auth_required"] = True
        else:
            result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result
