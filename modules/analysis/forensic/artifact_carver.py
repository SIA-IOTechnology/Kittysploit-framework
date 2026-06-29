#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

import json
import os
import re


class Module(Analysis):
    __info__ = {
        "name": "Forensic Artifact Carver",
        "author": ["KittySploit Team"],
        "description": "Carves lightweight forensic indicators such as URLs, emails, IPs and hashes from local files.",
        "tags": ["forensic", "dfir", "carving", "ioc", "evidence"],
    }

    path = OptString("", "File or directory to scan", required=True)
    recursive = OptBool(True, "Recurse into subdirectories", required=False)
    max_bytes_per_file = OptInteger(5242880, "Maximum bytes to read per file", required=False, advanced=True)
    max_files = OptInteger(3000, "Maximum files to scan", required=False, advanced=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    PATTERNS = {
        "urls": re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}"),
        "emails": re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "ipv4": re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        "md5": re.compile(rb"\b[a-fA-F0-9]{32}\b"),
        "sha1": re.compile(rb"\b[a-fA-F0-9]{40}\b"),
        "sha256": re.compile(rb"\b[a-fA-F0-9]{64}\b"),
    }

    def _iter_files(self, root):
        if os.path.isfile(root):
            yield root
            return
        if not os.path.isdir(root):
            return
        walker = os.walk(root) if self.recursive else [(root, [], os.listdir(root))]
        for base, _, names in walker:
            for name in sorted(names):
                path = os.path.join(base, name)
                if os.path.isfile(path):
                    yield path

    def _decode_matches(self, matches):
        values = set()
        for item in matches:
            try:
                values.add(item.decode("utf-8", errors="ignore").strip())
            except Exception:
                pass
        return sorted(v for v in values if v)

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
            max_bytes = max(1024, int(self.max_bytes_per_file))
        except Exception:
            max_bytes = 5242880
        try:
            file_limit = max(1, int(self.max_files))
        except Exception:
            file_limit = 3000

        print_info(f"Carving artifacts from: {root}")
        aggregate = {name: set() for name in self.PATTERNS}
        per_file = []
        errors = []

        for idx, file_path in enumerate(self._iter_files(root)):
            if idx >= file_limit:
                print_warning(f"Reached max_files limit ({file_limit}); stopping scan")
                break
            try:
                with open(file_path, "rb") as fp:
                    blob = fp.read(max_bytes)
                row = {"file": file_path, "size_read": len(blob), "artifacts": {}}
                for name, pattern in self.PATTERNS.items():
                    values = self._decode_matches(pattern.findall(blob))
                    if values:
                        row["artifacts"][name] = values[:100]
                        aggregate[name].update(values)
                if row["artifacts"]:
                    per_file.append(row)
            except Exception as exc:
                errors.append({"file": file_path, "error": str(exc)})

        artifact_counts = {name: len(values) for name, values in aggregate.items()}
        data = {
            "root": root,
            "files_with_artifacts": len(per_file),
            "artifact_counts": artifact_counts,
            "artifacts": {name: sorted(values)[:500] for name, values in aggregate.items()},
            "per_file": per_file,
            "error_count": len(errors),
            "errors": errors,
        }

        print_success(
            "Carving complete: "
            + ", ".join(f"{name}={count}" for name, count in artifact_counts.items())
        )
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
        root = "artifact_carver"
        nodes = [{"id": root, "label": "Artifact Carver", "group": "event", "icon": "search"}]
        edges = []
        for kind, values in data.get("artifacts", {}).items():
            for value in values[:15]:
                node_id = f"{kind}_{value}"
                nodes.append({"id": node_id, "label": value[:60], "group": kind, "icon": "ioc"})
                edges.append({"from": root, "to": node_id, "label": kind})
        return nodes, edges
