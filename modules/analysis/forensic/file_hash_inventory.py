#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

import hashlib
import json
import os
from datetime import datetime, timezone


class Module(Analysis):
    __info__ = {
        "name": "Forensic File Hash Inventory",
        "author": ["KittySploit Team"],
        "description": "Builds an offline file inventory with hashes, sizes and timestamps for evidence triage.",
        "tags": ["forensic", "dfir", "hash", "inventory", "evidence"],
    }

    path = OptString("", "File or directory to inventory", required=True)
    algorithms = OptString("sha256,md5", "Comma-separated hash algorithms", required=False)
    recursive = OptBool(True, "Recurse into subdirectories", required=False)
    max_files = OptInteger(5000, "Maximum files to process", required=False, advanced=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _parse_algorithms(self):
        available = set(hashlib.algorithms_available)
        algos = []
        for name in str(self.algorithms or "").split(","):
            algo = name.strip().lower()
            if algo and algo in available:
                algos.append(algo)
            elif algo:
                print_warning(f"Unsupported hash algorithm ignored: {algo}")
        return algos or ["sha256"]

    def _iter_files(self, root):
        if os.path.isfile(root):
            yield root
            return
        if not os.path.isdir(root):
            return
        if self.recursive:
            for base, _, files in os.walk(root):
                for name in sorted(files):
                    yield os.path.join(base, name)
        else:
            for name in sorted(os.listdir(root)):
                candidate = os.path.join(root, name)
                if os.path.isfile(candidate):
                    yield candidate

    def _hash_file(self, path, algos):
        hashers = {algo: hashlib.new(algo) for algo in algos}
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                for h in hashers.values():
                    h.update(chunk)
        return {algo: h.hexdigest() for algo, h in hashers.items()}

    def _iso_time(self, timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    def check(self):
        evidence_path = os.path.abspath(str(self.path or "").strip())
        if not evidence_path:
            print_error("path option is required")
            return False
        if not os.path.exists(evidence_path):
            print_error(f"Path not found: {evidence_path}")
            return False
        return True

    def run(self):
        root = os.path.abspath(str(self.path or "").strip())
        algos = self._parse_algorithms()
        try:
            limit = max(1, int(self.max_files))
        except Exception:
            limit = 5000

        print_info(f"Inventorying evidence path: {root}")
        print_info(f"Hash algorithms: {', '.join(algos)}")

        files = []
        errors = []
        for idx, file_path in enumerate(self._iter_files(root)):
            if idx >= limit:
                print_warning(f"Reached max_files limit ({limit}); stopping inventory")
                break
            try:
                stat = os.stat(file_path)
                files.append({
                    "path": file_path,
                    "relative_path": os.path.relpath(file_path, root if os.path.isdir(root) else os.path.dirname(root)),
                    "size": stat.st_size,
                    "mtime": self._iso_time(stat.st_mtime),
                    "ctime": self._iso_time(stat.st_ctime),
                    "atime": self._iso_time(stat.st_atime),
                    "hashes": self._hash_file(file_path, algos),
                })
            except Exception as exc:
                errors.append({"path": file_path, "error": str(exc)})

        data = {
            "root": root,
            "algorithms": algos,
            "file_count": len(files),
            "error_count": len(errors),
            "files": files,
            "errors": errors,
        }

        print_success(f"Inventory complete: files={len(files)} errors={len(errors)}")
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
        root = "forensic_inventory"
        nodes = [{"id": root, "label": "Forensic Inventory", "group": "event", "icon": "file"}]
        edges = []
        for i, row in enumerate(data.get("files", [])[:50]):
            node_id = f"file_{i}"
            nodes.append({"id": node_id, "label": os.path.basename(row.get("path", "file")), "group": "file", "icon": "file"})
            edges.append({"from": root, "to": node_id, "label": row.get("hashes", {}).get("sha256", "")[:12]})
        return nodes, edges
