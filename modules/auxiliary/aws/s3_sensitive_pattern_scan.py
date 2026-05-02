from kittysploit import *
import json
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "AWS S3 Sensitive Pattern Scan",
        "author": ["KittySploit Team"],
        "description": "List and scan exposed S3 objects for sensitive patterns (keys, tokens, credentials).",
        "tags": ["aws", "s3", "cloud", "secrets", "scan"],
    }

    target = OptString("", "S3 bucket name or URL", required=True)
    prefix = OptString("", "Optional object key prefix filter", required=False)
    max_files = OptString("300", "Maximum files to scan (0/all=unlimited)", required=False)
    max_bytes_per_file = OptString("250000", "Max bytes fetched per file for scanning", required=False)
    max_scan_seconds = OptString("0", "Maximum scan duration in seconds (0/all=unlimited)", required=False)
    progress_every = OptString("25", "Print progress every N scanned files", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    SENSITIVE_PATTERNS = [
        ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("aws_secret_access_key", re.compile(r"(?i)\baws(.{0,20})?(secret|access).{0,10}[=:]\s*[\"'][A-Za-z0-9/+=]{30,}[\"']")),
        ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
        ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("private_key_marker", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("password_assign", re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']")),
        ("secret_assign", re.compile(r"(?i)\b(secret|api[_-]?key|token|client[_-]?secret)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']")),
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _parse_max(self, value):
        raw = str(value).strip().lower()
        if raw in ("0", "all", "unlimited", "none", ""):
            return 0
        try:
            return max(1, int(raw))
        except Exception:
            return 0

    def _normalize_bucket(self, value):
        raw = str(value).strip()
        if not raw:
            return ""
        if raw.startswith(("http://", "https://")):
            try:
                parsed = urlparse(raw)
                host = parsed.hostname or ""
                if host.endswith(".s3.amazonaws.com"):
                    return host.replace(".s3.amazonaws.com", "")
                if host.startswith("s3.") and ".amazonaws.com" in host:
                    path_parts = [p for p in (parsed.path or "").split("/") if p]
                    return path_parts[0] if path_parts else ""
                return host.split(".")[0]
            except Exception:
                return ""
        return raw

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
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = (scheme == "https")
            return self.http_request(method="GET", path=path, allow_redirects=True, timeout=timeout_seconds)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _list_objects(self, bucket, prefix, timeout_seconds, max_files):
        token = ""
        objects = []

        def _strip_tag(tag):
            return tag.split("}", 1)[1] if "}" in tag else tag

        while True:
            if max_files > 0:
                remaining = max_files - len(objects)
                if remaining <= 0:
                    break
                page_size = min(1000, remaining)
            else:
                page_size = 1000

            query = f"list-type=2&max-keys={page_size}"
            if prefix:
                query += f"&prefix={quote(prefix)}"
            if token:
                query += f"&continuation-token={quote(token)}"
            url = f"https://{bucket}.s3.amazonaws.com/?{query}"
            resp = self._http_get_url(url, timeout_seconds)
            if not resp or resp.status_code != 200:
                break
            try:
                root = ET.fromstring(resp.text or "")
            except Exception:
                break

            for elem in root.iter():
                if _strip_tag(elem.tag) == "Contents":
                    key = ""
                    for child in elem:
                        if _strip_tag(child.tag) == "Key":
                            key = (child.text or "").strip()
                            break
                    if key:
                        objects.append(key)

            token = ""
            for elem in root.iter():
                if _strip_tag(elem.tag) in ("NextContinuationToken", "NextMarker"):
                    token = (elem.text or "").strip()
                    if token:
                        break
            if not token:
                break

        if max_files > 0:
            return objects[:max_files]
        return objects

    def _scan_text(self, text):
        hits = []
        for name, rx in self.SENSITIVE_PATTERNS:
            for m in rx.finditer(text):
                snippet = text[max(0, m.start() - 30): m.end() + 30].replace("\n", " ")
                hits.append({
                    "pattern": name,
                    "match_preview": snippet[:180],
                })
                if len(hits) >= 40:
                    return hits
        return hits

    def run(self):
        bucket = self._normalize_bucket(self.target)
        if not bucket:
            print_error("target must be an S3 bucket name or URL")
            return {"error": "invalid target"}

        prefix = str(self.prefix).strip()
        timeout_seconds = self._to_int(self.timeout, 10)
        max_files = self._parse_max(self.max_files)
        max_bytes = self._to_int(self.max_bytes_per_file, 250000)
        max_scan_seconds = self._parse_max(self.max_scan_seconds)
        progress_every = self._to_int(self.progress_every, 25)

        print_info(f"Scanning S3 patterns in {bucket}")
        files = self._list_objects(bucket, prefix, timeout_seconds, max_files)
        if not files:
            print_warning("No objects listed or inaccessible bucket.")
            return {
                "target": f"{bucket}.s3.amazonaws.com",
                "count_files": 0,
                "count_flagged": 0,
                "findings": [],
                "risk_level": "LOW",
                "risk_score": 0,
            }
        print_info(f"Objects discovered for scan: {len(files)}")

        findings = []
        scanned = 0
        started = time.time()
        for key in files:
            if max_scan_seconds > 0 and (time.time() - started) > max_scan_seconds:
                print_warning(f"Max scan duration reached ({max_scan_seconds}s), stopping early.")
                break

            url = f"https://{bucket}.s3.amazonaws.com/{quote(key, safe='/')}"
            resp = self._http_get_url(url, timeout_seconds)
            scanned += 1
            if progress_every > 0 and scanned % progress_every == 0:
                print_status(
                    f"Scan progress: scanned={scanned}/{len(files)} "
                    f"flagged={len(findings)} elapsed={int(time.time() - started)}s"
                )

            if not resp or resp.status_code != 200:
                continue
            body = resp.text or ""
            if len(body) > max_bytes:
                body = body[:max_bytes]
            hits = self._scan_text(body)
            if hits:
                findings.append({
                    "file": key,
                    "url": url,
                    "hits": hits,
                    "hit_count": len(hits),
                })

        risk_score = min(10, (len(findings) * 2) + sum(min(2, f["hit_count"] // 5) for f in findings))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")
        result = {
            "target": f"{bucket}.s3.amazonaws.com",
            "provider": "aws_s3",
            "bucket": bucket,
            "count_files": len(files),
            "count_scanned": scanned,
            "count_flagged": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings[:300],
        }

        print_success(
            f"Sensitive scan done: files={len(files)} scanned={scanned} "
            f"flagged={len(findings)} risk={risk_level}({risk_score})"
        )
        for f in findings[:20]:
            print_warning(f"  {f.get('file')} -> {f.get('hit_count')} hit(s)")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(result, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return result

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", "s3-sensitive-scan")
        nodes = [{
            "id": target,
            "label": target,
            "group": "hostname",
            "icon": "🟧",
            "custom_info": (
                f"Risk: {data.get('risk_level', 'LOW')} ({data.get('risk_score', 0)})\n"
                f"Scanned: {data.get('count_scanned', 0)}\n"
                f"Flagged: {data.get('count_flagged', 0)}"
            ),
        }]
        edges = []
        for i, f in enumerate(data.get("findings", [])[:50]):
            nid = f"s3_sens_{i}"
            nodes.append({
                "id": nid,
                "label": f"{f.get('file')} ({f.get('hit_count', 0)})"[:95],
                "group": "risk",
                "icon": "🔎",
                "custom_info": "\n".join(
                    [f"File: {f.get('file', 'n/a')}", f"Hits: {f.get('hit_count', 0)}"]
                    + [f"- {h.get('pattern')}: {h.get('match_preview')}" for h in f.get("hits", [])[:6]]
                ),
            })
            edges.append({"from": target, "to": nid, "label": "sensitive_hit", "custom_info": "Sensitive pattern detected"})
        return nodes, edges
