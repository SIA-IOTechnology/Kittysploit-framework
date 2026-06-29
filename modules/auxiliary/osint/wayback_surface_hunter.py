from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Wayback Surface Hunter",
        "author": ["KittySploit Team"],
        "description": (
            "Mine Internet Archive (Wayback CDX) for historical URLs and flag forgotten "
            "sensitive endpoints — admin panels, configs, backups, API docs, and debug paths."
        ),
        "tags": ["osint", "passive", "wayback", "historical", "surface"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    max_urls = OptString("500", "Maximum unique URLs to fetch from CDX", required=False)
    min_score = OptString("40", "Minimum sensitivity score to keep (0-100)", required=False)
    timeout = OptString("15", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    SENSITIVE_RULES = [
        (re.compile(r"(^|/)(admin|administrator|wp-admin|phpmyadmin|manager)(/|$)", re.I), "admin_panel", 85),
        (re.compile(r"\.env(\.|$|/)", re.I), "env_file", 95),
        (re.compile(r"\.git(/|$)", re.I), "git_exposure", 90),
        (re.compile(r"(backup|dump|sql|\.bak|\.old|\.swp|\.tar|\.zip|\.gz)(/|\.|$)", re.I), "backup_artifact", 88),
        (re.compile(r"(swagger|openapi|api-docs|graphql)(/|\.|$)", re.I), "api_documentation", 75),
        (re.compile(r"(phpinfo|trace|debug|stacktrace|actuator)(/|\.|$)", re.I), "debug_endpoint", 82),
        (re.compile(r"(config|settings|credentials|secret|token|password)(/|\.|$)", re.I), "config_hint", 70),
        (re.compile(r"(login|signin|auth|oauth|sso)(/|\.|$)", re.I), "auth_endpoint", 55),
        (re.compile(r"(\.sql|\.log|\.conf|\.ini|\.yaml|\.yml|\.json)(/|$|\?)", re.I), "sensitive_extension", 65),
        (re.compile(r"(internal|staging|dev|test|uat|preprod)(/|\.|$)", re.I), "nonprod_host", 60),
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_domain(self, value):
        domain = str(value).strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/", 1)[0].strip(".")
        if "@" in domain or not domain or "." not in domain:
            return None
        return domain

    def _http_get_url(self, url, timeout_seconds, headers=None):
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
            self.ssl = scheme == "https"
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
                headers=headers or {"User-Agent": "KittyOSINT/1.0"},
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _query_cdx(self, domain, limit, timeout_seconds):
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original,statuscode,mimetype,timestamp"
            f"&collapse=urlkey&limit={limit}"
        )
        resp = self._http_get_url(url, timeout_seconds)
        if not resp or resp.status_code != 200:
            return []
        try:
            rows = resp.json()
        except Exception:
            return []
        if not rows or len(rows) < 2:
            return []
        headers = rows[0]
        findings = []
        for row in rows[1:]:
            entry = dict(zip(headers, row))
            original = entry.get("original", "")
            if not original:
                continue
            findings.append({
                "url": original,
                "status_code": entry.get("statuscode"),
                "mimetype": entry.get("mimetype"),
                "last_seen": entry.get("timestamp"),
            })
        return findings

    def _score_url(self, url):
        path = urlparse(url).path or "/"
        best = {"category": None, "score": 0, "matches": []}
        for pattern, category, score in self.SENSITIVE_RULES:
            if pattern.search(path) or pattern.search(url):
                best["matches"].append(category)
                if score > best["score"]:
                    best["score"] = score
                    best["category"] = category
        return best

    def _risk_level(self, findings):
        if any(f.get("score", 0) >= 85 for f in findings):
            return "HIGH"
        if any(f.get("score", 0) >= 60 for f in findings):
            return "MEDIUM"
        if findings:
            return "LOW"
        return "NONE"

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid domain target"}

        max_urls = self._to_int(self.max_urls, 500)
        min_score = min(100, self._to_int(self.min_score, 40))
        timeout_seconds = self._to_int(self.timeout, 15)

        print_info(f"Querying Wayback CDX for *.{domain} (limit={max_urls})...")
        raw_entries = self._query_cdx(domain, max_urls, timeout_seconds)
        if not raw_entries:
            print_warning("No Wayback CDX data returned (domain may be absent from archive or source unavailable)")
            return {
                "target": domain,
                "total_archived_urls": 0,
                "sensitive_count": 0,
                "risk_level": "NONE",
                "findings": [],
            }

        scored = []
        for entry in raw_entries:
            meta = self._score_url(entry["url"])
            if meta["score"] < min_score:
                continue
            scored.append({
                **entry,
                "score": meta["score"],
                "category": meta["category"],
                "matches": meta["matches"],
            })

        scored.sort(key=lambda x: (-x.get("score", 0), x.get("url", "")))
        risk = self._risk_level(scored)

        categories = {}
        for f in scored:
            cat = f.get("category") or "other"
            categories[cat] = categories.get(cat, 0) + 1

        data = {
            "target": domain,
            "total_archived_urls": len(raw_entries),
            "sensitive_count": len(scored),
            "risk_level": risk,
            "category_breakdown": categories,
            "findings": scored[:100],
        }

        print_success(
            f"Wayback scan: {len(raw_entries)} archived URL(s), "
            f"{len(scored)} sensitive (risk={risk})"
        )
        for f in scored[:12]:
            print_info(
                f"  [{f.get('score')}] {f.get('category')}: {f.get('url')} "
                f"(archived {f.get('last_seen', '?')})"
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
        target = data.get("target", self.target)
        nodes = []
        edges = []
        for i, f in enumerate(data.get("findings", [])[:20]):
            nid = f"wayback_{i}"
            label = f"{f.get('category', 'url')}: {urlparse(f.get('url', '')).path[:40]}"
            nodes.append({"id": nid, "label": label, "group": "url", "icon": "🕰️"})
            edges.append({"from": target, "to": nid, "label": "archived"})
        return nodes, edges
