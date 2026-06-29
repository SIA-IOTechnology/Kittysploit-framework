#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

import gzip
import json
import os
import re
from collections import Counter


class Module(Analysis):
    __info__ = {
        "name": "Forensic Log Triage",
        "author": ["KittySploit Team"],
        "description": "Scans local logs for authentication failures, suspicious commands, IPs and error indicators.",
        "tags": ["forensic", "dfir", "logs", "linux", "triage"],
    }

    path = OptString("", "Log file or directory to scan", required=True)
    recursive = OptBool(True, "Recurse into subdirectories", required=False)
    max_lines = OptInteger(200000, "Maximum lines to scan", required=False, advanced=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    MARKERS = {
        "auth_failure": re.compile(r"(failed password|authentication failure|invalid user|login incorrect)", re.I),
        "success_login": re.compile(r"(accepted password|accepted publickey|session opened|successful login)", re.I),
        "privilege": re.compile(r"(\bsudo\b|su:|pam_unix\(sudo|root privileges|uid=0)", re.I),
        "persistence": re.compile(r"(crontab|authorized_keys|systemctl enable|rc\.local|\.service)", re.I),
        "download_exec": re.compile(r"(curl |wget |chmod \+x|/tmp/|/dev/shm/|powershell|certutil)", re.I),
        "error": re.compile(r"(segfault|panic|traceback|fatal|permission denied|access denied)", re.I),
    }

    def _iter_logs(self, root):
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

    def _open_text(self, path):
        if path.endswith(".gz"):
            return gzip.open(path, "rt", errors="replace")
        return open(path, "r", errors="replace")

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
            line_limit = max(1, int(self.max_lines))
        except Exception:
            line_limit = 200000

        print_info(f"Scanning logs under: {root}")
        marker_counts = Counter()
        ip_counts = Counter()
        samples = []
        errors = []
        lines_seen = 0
        files_seen = 0

        for log_path in self._iter_logs(root):
            if lines_seen >= line_limit:
                print_warning(f"Reached max_lines limit ({line_limit}); stopping scan")
                break
            files_seen += 1
            try:
                with self._open_text(log_path) as fp:
                    for line_no, line in enumerate(fp, 1):
                        if lines_seen >= line_limit:
                            break
                        lines_seen += 1
                        matched = []
                        for name, pattern in self.MARKERS.items():
                            if pattern.search(line):
                                marker_counts[name] += 1
                                matched.append(name)
                        for ip in self.IP_RE.findall(line):
                            ip_counts[ip] += 1
                        if matched and len(samples) < 100:
                            samples.append({
                                "file": log_path,
                                "line": line_no,
                                "markers": matched,
                                "text": line.strip()[:500],
                            })
            except Exception as exc:
                errors.append({"file": log_path, "error": str(exc)})

        score = (
            marker_counts["auth_failure"]
            + marker_counts["privilege"] * 2
            + marker_counts["persistence"] * 3
            + marker_counts["download_exec"] * 3
        )
        risk_level = "LOW" if score < 10 else ("MEDIUM" if score < 50 else "HIGH")
        data = {
            "root": root,
            "files_scanned": files_seen,
            "lines_scanned": lines_seen,
            "marker_counts": dict(marker_counts),
            "top_ips": [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(25)],
            "samples": samples,
            "error_count": len(errors),
            "errors": errors,
            "risk_score": score,
            "risk_level": risk_level,
        }

        print_success(f"Log triage complete: files={files_seen} lines={lines_seen} risk={risk_level}")
        if data["top_ips"]:
            print_info("Top IPs: " + ", ".join(f"{row['ip']}({row['count']})" for row in data["top_ips"][:5]))
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
        root = "log_triage"
        nodes = [{"id": root, "label": "Log Triage", "group": "event", "icon": "log"}]
        edges = []
        for row in data.get("top_ips", [])[:20]:
            node_id = f"ip_{row.get('ip')}"
            nodes.append({"id": node_id, "label": row.get("ip"), "group": "ip", "icon": "ip"})
            edges.append({"from": root, "to": node_id, "label": str(row.get("count", 0))})
        return nodes, edges
