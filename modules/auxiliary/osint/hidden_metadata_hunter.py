from kittysploit import *
import json
import os
import subprocess
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Hidden Metadata Hunter",
        "author": ["KittySploit Team"],
        "description": "Extract sensitive metadata from public files using exiftool/pdfinfo/olevba when available.",
        "tags": ["osint", "metadata", "files", "passive"],
    }

    target = OptString("", "Single file path or file URL (alias for targets)", required=False)
    targets = OptString("", "Comma-separated local file paths or file URLs", required=True)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _run_cmd(self, cmd):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if res.returncode != 0:
                return ""
            return (res.stdout or "").strip()
        except Exception:
            return ""

    def _detect_tools(self):
        return {
            "exiftool": bool(self._run_cmd(["bash", "-lc", "command -v exiftool"])),
            "pdfinfo": bool(self._run_cmd(["bash", "-lc", "command -v pdfinfo"])),
            "olevba": bool(self._run_cmd(["bash", "-lc", "command -v olevba"])),
        }

    def _http_get_url(self, url, timeout_seconds):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        old_target = self.targets
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.targets = host
            self.port = int(port)
            self.ssl = (scheme == "https")
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.targets = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _download_url(self, url, timeout_seconds):
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200 or not resp.content:
            return None
        basename = os.path.basename(urlparse(url).path) or "download.bin"
        local_path = f"/tmp/kittyosint_{basename}"
        try:
            with open(local_path, "wb") as fp:
                fp.write(resp.content)
            return local_path
        except Exception:
            return None

    def _extract_local_file(self, path, tools):
        findings = {
            "file": path,
            "exists": os.path.exists(path),
            "metadata": {},
            "sensitive_hints": [],
        }
        if not findings["exists"]:
            return findings

        lower = path.lower()
        if tools["exiftool"] and lower.endswith((".jpg", ".jpeg", ".png", ".webp", ".tiff", ".gif", ".docx", ".xlsx", ".pptx", ".pdf")):
            exif_raw = self._run_cmd(["exiftool", "-j", path])
            if exif_raw:
                findings["metadata"]["exiftool_raw"] = exif_raw[:20000]

        if tools["pdfinfo"] and lower.endswith(".pdf"):
            pdf_raw = self._run_cmd(["pdfinfo", path])
            if pdf_raw:
                findings["metadata"]["pdfinfo_raw"] = pdf_raw[:15000]

        if tools["olevba"] and lower.endswith((".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm")):
            vba_raw = self._run_cmd(["olevba", path])
            if vba_raw:
                findings["metadata"]["olevba_raw"] = vba_raw[:20000]

        merged = json.dumps(findings["metadata"]).lower()
        for marker in ["author", "creator", "company", "lastsavedby", "template", "machine", "username", "email", "internal", "secret", "token"]:
            if marker in merged:
                findings["sensitive_hints"].append(marker)
        findings["sensitive_hints"] = sorted(set(findings["sensitive_hints"]))
        return findings

    def run(self):
        combined = str(self.targets).strip()
        if not combined and str(self.target).strip():
            combined = str(self.target).strip()
        entries = [x.strip() for x in combined.split(",") if x.strip()]
        if not entries:
            print_status("No file targets provided; skipping metadata extraction")
            return {
                "targets_count": 0,
                "tooling": self._detect_tools(),
                "count_sensitive_files": 0,
                "risk_score": 0,
                "risk_level": "LOW",
                "files": [],
                "skipped": True,
                "reason": "no_targets",
            }
        timeout_seconds = self._to_int(self.timeout, 10)
        tools = self._detect_tools()
        print_info(f"Metadata extraction for {len(entries)} target(s)")
        print_info(f"Available tools: {', '.join([k for k, v in tools.items() if v]) or 'none'}")

        results = []
        for item in entries:
            local_path = item
            downloaded = False
            if item.startswith(("http://", "https://")):
                local_path = self._download_url(item, timeout_seconds)
                downloaded = True
            if not local_path:
                results.append({"file": item, "exists": False, "metadata": {}, "sensitive_hints": []})
                continue
            row = self._extract_local_file(local_path, tools)
            row["source"] = item
            row["downloaded"] = downloaded
            results.append(row)

        sensitive = [r for r in results if r.get("sensitive_hints")]
        risk_score = min(10, len(sensitive) * 2 + (1 if not any(tools.values()) else 0))
        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")

        data = {
            "targets_count": len(entries),
            "tooling": tools,
            "count_sensitive_files": len(sensitive),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "files": results,
        }
        print_success(
            f"Metadata hunt done: sensitive_files={data['count_sensitive_files']} risk={risk_level}"
        )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        root = "metadata_hunt"
        nodes = [{"id": root, "label": "Metadata Hunt", "group": "event", "icon": "🧾"}]
        edges = []
        for i, row in enumerate(data.get("files", [])[:20]):
            if not row.get("sensitive_hints"):
                continue
            nid = f"meta_{i}"
            nodes.append({
                "id": nid,
                "label": os.path.basename(str(row.get("source", "file"))),
                "group": "file",
                "icon": "📄",
            })
            edges.append({"from": root, "to": nid, "label": ",".join(row.get("sensitive_hints", [])[:3])})
        return nodes, edges
