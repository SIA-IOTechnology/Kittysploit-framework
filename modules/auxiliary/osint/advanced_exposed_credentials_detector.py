from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Advanced Exposed Credentials Detector",
        "author": ["KittySploit Team"],
        "description": "Detect likely exposed credentials from public text sources using dynamic regex and correlation scoring.",
        "tags": ["osint", "credentials", "leak", "passive"],
    }

    target = OptString("", "Target domain/email/keyword", required=True)
    sources = OptString("", "Comma-separated source URLs to inspect (paste/forum/git mirrors)", required=False)
    max_findings = OptString("150", "Maximum findings to keep", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    EMAIL_RX = re.compile(r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    USER_PASS_RX = re.compile(
        r"(?i)\b(?:user(?:name)?|login|mail|email)\b\s*[:=]\s*([^\s:;,\"]{2,})\s*[|:;,]\s*\b(?:pass(?:word)?|pwd|token|secret)\b\s*[:=]\s*([^\s\"']{4,})"
    )
    KEYVALUE_RX = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|client[_-]?secret|aws_access_key_id|aws_secret_access_key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-\/+=]{8,})[\"']?"
    )
    HASH_RX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _score_finding(self, finding):
        score = 0
        kind = finding.get("kind", "")
        value = str(finding.get("value", ""))
        if kind == "user_pass_pair":
            score += 5
        elif kind == "secret_kv":
            score += 4
        elif kind == "email_hint":
            score += 2
        if len(value) >= 24:
            score += 1
        if self.target and str(self.target).lower() in str(finding.get("context", "")).lower():
            score += 2
        return min(10, score)

    def _extract_candidates(self, text, source_url):
        findings = []
        for user, pwd in self.USER_PASS_RX.findall(text):
            findings.append({
                "kind": "user_pass_pair",
                "value": f"{user}:{pwd[:4]}***",
                "context": f"user/pass pattern in {source_url}",
                "source": source_url,
            })
        for key_name, key_val in self.KEYVALUE_RX.findall(text):
            findings.append({
                "kind": "secret_kv",
                "value": f"{key_name}={key_val[:6]}***",
                "context": f"secret-like assignment in {source_url}",
                "source": source_url,
            })
        for email in self.EMAIL_RX.findall(text):
            findings.append({
                "kind": "email_hint",
                "value": email,
                "context": f"email mention in {source_url}",
                "source": source_url,
            })
        for h in self.HASH_RX.findall(text):
            findings.append({
                "kind": "hash_hint",
                "value": h[:10] + "***",
                "context": f"hash-like token in {source_url}",
                "source": source_url,
            })
        return findings

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
            return self.http_request("GET", path=path, timeout=timeout_seconds, allow_redirects=True)
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def run(self):
        needle = str(self.target).strip().lower()
        if not needle:
            print_error("target is required")
            return {"error": "target is required"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_findings = self._to_int(self.max_findings, 150)
        source_urls = [x.strip() for x in str(self.sources).split(",") if x.strip()]
        if not source_urls:
            # UI run-all only provides target; fallback to likely public pages for passive scraping.
            normalized = needle.replace("https://", "").replace("http://", "").split("/", 1)[0]
            if "." in normalized and " " not in normalized:
                source_urls = [f"https://{normalized}", f"http://{normalized}"]
            else:
                source_urls = []
            if not source_urls:
                print_status("No explicit sources provided; skipping credential source scan")
                return {
                    "target": needle,
                    "sources_scanned": 0,
                    "count_findings": 0,
                    "count_high_confidence": 0,
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "findings": [],
                    "skipped": True,
                    "reason": "no_sources",
                }

        print_info(f"Scanning {len(source_urls)} source(s) for credential exposure signals")
        all_findings = []
        for url in source_urls:
            resp = self._http_get_url(url, timeout_seconds)
            if not resp or resp.status_code != 200 or not resp.text:
                continue
            text = resp.text
            extracted = self._extract_candidates(text, url)
            for f in extracted:
                f["score"] = self._score_finding(f)
                all_findings.append(f)

        # Correlation: same value seen in multiple sources is stronger.
        value_sources = {}
        for f in all_findings:
            value_sources.setdefault(f["value"], set()).add(f["source"])
        for f in all_findings:
            ref_count = len(value_sources.get(f["value"], []))
            if ref_count >= 2:
                f["score"] = min(10, int(f.get("score", 0)) + 2)
                f["correlated"] = True
                f["source_count"] = ref_count
            else:
                f["correlated"] = False
                f["source_count"] = ref_count

        all_findings.sort(key=lambda x: int(x.get("score", 0)), reverse=True)
        selected = all_findings[:max_findings]
        high = [x for x in selected if int(x.get("score", 0)) >= 7]
        risk_score = min(10, len(high) + (2 if len(selected) >= 40 else 0))
        risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")

        data = {
            "target": needle,
            "sources_scanned": len(source_urls),
            "count_findings": len(selected),
            "count_high_confidence": len(high),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": selected,
        }
        print_success(
            f"Credential exposure scan done: findings={data['count_findings']} high={data['count_high_confidence']} risk={risk_level}"
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
        root = data.get("target", self.target)
        nodes = []
        edges = []
        for i, item in enumerate(data.get("findings", [])[:20]):
            nid = f"cred_{i}_{root}"
            nodes.append({
                "id": nid,
                "label": f"{item.get('kind')} ({item.get('score')})",
                "group": "finding",
                "icon": "🔑",
            })
            edges.append({"from": root, "to": nid, "label": item.get("source_count", 1)})
        return nodes, edges
