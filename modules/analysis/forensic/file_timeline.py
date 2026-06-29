#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

import json
import os
from datetime import datetime, timezone


class Module(Analysis):
    __info__ = {
        "name": "Forensic File Timeline",
        "author": ["KittySploit Team"],
        "description": "Creates a sorted filesystem timeline from MAC timestamps for local evidence triage.",
        "tags": ["forensic", "dfir", "timeline", "filesystem", "evidence"],
    }

    path = OptString("", "File or directory to timeline", required=True)
    recursive = OptBool(True, "Recurse into subdirectories", required=False)
    include_dirs = OptBool(False, "Include directory entries", required=False)
    max_entries = OptInteger(10000, "Maximum filesystem entries to process", required=False, advanced=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _iso_time(self, timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    def _iter_paths(self, root):
        if os.path.isfile(root) or (self.include_dirs and os.path.isdir(root)):
            yield root
        if not os.path.isdir(root):
            return
        if self.recursive:
            for base, dirs, files in os.walk(root):
                names = files + (dirs if self.include_dirs else [])
                for name in sorted(names):
                    yield os.path.join(base, name)
        else:
            for name in sorted(os.listdir(root)):
                candidate = os.path.join(root, name)
                if os.path.isfile(candidate) or (self.include_dirs and os.path.isdir(candidate)):
                    yield candidate

    def check(self):
        root = os.path.abspath(str(self.path or "").strip())
        if not root:
            print_error("path option is required")
            return False
        if not os.path.exists(root):
            print_error(f"Path not found: {root}")
            return False
        return True

    def run(self):
        root = os.path.abspath(str(self.path or "").strip())
        try:
            limit = max(1, int(self.max_entries))
        except Exception:
            limit = 10000

        print_info(f"Building timeline for: {root}")
        events = []
        errors = []
        for idx, item in enumerate(self._iter_paths(root)):
            if idx >= limit:
                print_warning(f"Reached max_entries limit ({limit}); stopping timeline")
                break
            try:
                stat = os.stat(item)
                rel = os.path.relpath(item, root if os.path.isdir(root) else os.path.dirname(root))
                kind = "directory" if os.path.isdir(item) else "file"
                for event_type, timestamp in (("modified", stat.st_mtime), ("changed", stat.st_ctime), ("accessed", stat.st_atime)):
                    events.append({
                        "timestamp": self._iso_time(timestamp),
                        "event": event_type,
                        "path": item,
                        "relative_path": rel,
                        "type": kind,
                        "size": stat.st_size,
                    })
            except Exception as exc:
                errors.append({"path": item, "error": str(exc)})

        events.sort(key=lambda row: row["timestamp"])
        data = {
            "root": root,
            "event_count": len(events),
            "error_count": len(errors),
            "events": events,
            "errors": errors,
        }

        print_success(f"Timeline complete: events={len(events)} errors={len(errors)}")
        if events:
            print_info(f"First event: {events[0]['timestamp']} {events[0]['event']} {events[0]['relative_path']}")
            print_info(f"Last event: {events[-1]['timestamp']} {events[-1]['event']} {events[-1]['relative_path']}")
        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict):
            return [], []
        root = "forensic_timeline"
        nodes = [{"id": root, "label": "Forensic Timeline", "group": "event", "icon": "clock"}]
        edges = []
        seen = set()
        for row in data.get("events", [])[:80]:
            label = row.get("relative_path", "file")
            if label in seen:
                continue
            seen.add(label)
            node_id = f"timeline_{len(seen)}"
            nodes.append({"id": node_id, "label": os.path.basename(label), "group": "file", "icon": "file"})
            edges.append({"from": root, "to": node_id, "label": row.get("event", "")})
        return nodes, edges
