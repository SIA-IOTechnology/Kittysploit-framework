#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional


def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", str(name or "").strip()).strip("-._")[:80] or "view"


class InvestigationStore:
    """Named filter views + annotations persisted on disk."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = os.path.abspath(base_dir or os.path.join(os.path.dirname(__file__), "investigation_data"))
        os.makedirs(self.base_dir, exist_ok=True)
        self._views_path = os.path.join(self.base_dir, "views.json")
        self._annotations_path = os.path.join(self.base_dir, "annotations.json")

    def _read_json(self, path: str, default: Any) -> Any:
        if not os.path.isfile(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return default

    def _write_json(self, path: str, data: Any) -> None:
        tmp = f"{path}.{uuid.uuid4().hex}.tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(tmp, path)

    def list_views(self) -> Dict[str, Any]:
        data = self._read_json(self._views_path, {})
        return {"views": [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in data.items()]}

    def save_view(self, name: str, filters: Dict[str, Any], description: str = "") -> Dict[str, Any]:
        key = _slug(name)
        data = self._read_json(self._views_path, {})
        data[key] = {
            "display_name": name.strip() or key,
            "filters": filters,
            "description": description,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self._write_json(self._views_path, data)
        return {"status": "saved", "view_id": key}

    def get_view(self, name: str) -> Dict[str, Any]:
        data = self._read_json(self._views_path, {})
        key = _slug(name)
        if key not in data:
            return {"error": f"View not found: {key}"}
        return {"view": {**data[key], "id": key}}

    def delete_view(self, name: str) -> Dict[str, Any]:
        data = self._read_json(self._views_path, {})
        key = _slug(name)
        if key in data:
            del data[key]
            self._write_json(self._views_path, data)
        return {"status": "deleted", "view_id": key}

    def list_annotations(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        data = self._read_json(self._annotations_path, {})
        if session_id:
            return {"annotations": data.get(session_id, [])}
        return {"sessions": list(data.keys()), "annotations_by_session": data}

    def add_annotation(
        self,
        session_id: str,
        flow_id: str,
        note: str,
        tags: Optional[List[str]] = None,
        ticket_url: str = "",
        status: str = "to verify",
        assignee: str = "",
    ) -> Dict[str, Any]:
        sid = str(session_id or "").strip() or "default"
        data = self._read_json(self._annotations_path, {})
        bucket = data.setdefault(sid, [])
        entry = {
            "id": uuid.uuid4().hex[:16],
            "flow_id": flow_id,
            "note": note,
            "tags": tags or [],
            "ticket_url": ticket_url.strip(),
            "status": str(status or "to verify").strip()[:40],
            "assignee": str(assignee or "").strip()[:120],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        bucket.append(entry)
        self._write_json(self._annotations_path, data)
        return {"status": "saved", "annotation": entry}

    def annotations_for_session(self, session_id: str) -> List[Dict[str, Any]]:
        data = self._read_json(self._annotations_path, {})
        return list(data.get(session_id, []))
