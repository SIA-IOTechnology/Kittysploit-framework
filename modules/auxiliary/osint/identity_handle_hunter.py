from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Identity Handle Hunter",
        "author": ["KittySploit Team"],
        "description": "Discover likely public profiles for a username/email/name and score confidence.",
        "tags": ["osint", "identity", "passive"],
    }

    query = OptString("", "Identity query (username/email/name)", required=True)
    query_type = OptString("username", "Query type: username|email|name", required=False)
    max_results = OptString("30", "Maximum result entries to keep", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    PROFILE_PATTERNS = [
        ("github", "https://github.com/{handle}"),
        ("gitlab", "https://gitlab.com/{handle}"),
        ("x", "https://x.com/{handle}"),
        ("reddit", "https://www.reddit.com/user/{handle}"),
        ("medium", "https://medium.com/@{handle}"),
        ("devto", "https://dev.to/{handle}"),
        ("keybase", "https://keybase.io/{handle}"),
        ("aboutme", "https://about.me/{handle}"),
        ("producthunt", "https://www.producthunt.com/@{handle}"),
        ("gravatar", "https://gravatar.com/{handle}"),
    ]

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
            self.ssl = (scheme == "https")
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
                headers=headers or {},
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _extract_handles(self, query, query_type):
        handles = set()
        q = str(query).strip()
        qtype = str(query_type).strip().lower()

        if qtype == "email" and "@" in q:
            local = q.split("@", 1)[0]
            if local:
                handles.add(local)
            # Common variations from mailbox local-part.
            for variant in re.split(r"[._\-+]", local):
                if len(variant) >= 3:
                    handles.add(variant)
        elif qtype == "name":
            base = re.sub(r"[^a-zA-Z0-9 ]", " ", q)
            parts = [p.lower() for p in base.split() if p]
            if parts:
                handles.add("".join(parts))
                handles.add(".".join(parts))
                handles.add("_".join(parts))
                if len(parts) >= 2:
                    handles.add(parts[0] + parts[-1])
        else:
            cleaned = re.sub(r"[^a-zA-Z0-9._\-]", "", q)
            if cleaned:
                handles.add(cleaned)

        # Avoid noisy very short candidates.
        return sorted(h for h in handles if len(h) >= 3)

    def _check_profile_url(self, platform, url, timeout_seconds):
        headers = {"User-Agent": "KittyOSINT/1.0"}
        try:
            resp = self._http_get_url(url, timeout_seconds, headers=headers)
            if not resp:
                raise Exception("HTTP request failed")
            code = resp.status_code
            title = ""
            if resp.text:
                m = re.search(r"(?is)<title[^>]*>(.*?)</title>", resp.text[:5000])
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

            # 200 is generally a hit; some platforms return 200 for "not found"
            # so keep confidence moderate and let title heuristics increase it.
            confidence = 50
            exists = code == 200
            if exists and any(k in title.lower() for k in ["not found", "page not found", "doesn’t exist", "doesn't exist"]):
                exists = False
                confidence = 0
            elif exists:
                confidence = 65
                if title and platform in title.lower():
                    confidence = 75

            return {
                "platform": platform,
                "url": resp.url or url,
                "http_status": code,
                "exists": exists,
                "confidence": confidence if exists else 0,
                "title": title,
            }
        except Exception as e:
            return {
                "platform": platform,
                "url": url,
                "http_status": None,
                "exists": False,
                "confidence": 0,
                "error": str(e),
            }

    def run(self):
        query = str(self.query).strip()
        query_type = str(self.query_type).strip().lower() or "username"
        timeout_seconds = self._to_int(self.timeout, 8)
        max_results = self._to_int(self.max_results, 30)

        if not query:
            print_error("query is required")
            return {"error": "query is required"}

        if query_type not in ("username", "email", "name"):
            print_warning(f"Unknown query_type '{query_type}', fallback to 'username'")
            query_type = "username"

        handles = self._extract_handles(query, query_type)
        if not handles:
            print_error("Could not derive any valid handle from query")
            return {"error": "no valid handle derived"}

        print_info(f"Target query: {query} ({query_type})")
        print_info(f"Generated {len(handles)} handle candidate(s): {', '.join(handles[:5])}")

        results = []
        for handle in handles:
            for platform, pattern in self.PROFILE_PATTERNS:
                url = pattern.format(handle=handle)
                entry = self._check_profile_url(platform, url, timeout_seconds)
                entry["handle"] = handle
                if entry.get("exists"):
                    results.append(entry)

        # Deduplicate by platform/url.
        unique = {}
        for item in results:
            key = (item.get("platform"), item.get("url"))
            if key not in unique or item.get("confidence", 0) > unique[key].get("confidence", 0):
                unique[key] = item
        found = sorted(unique.values(), key=lambda x: x.get("confidence", 0), reverse=True)[:max_results]

        data = {
            "target": query,
            "query_type": query_type,
            "handles_tested": handles,
            "count": len(found),
            "findings": found,
        }

        if found:
            print_success(f"Found {len(found)} likely profile(s)")
            for item in found[:15]:
                print_info(
                    f"  [{item.get('platform')}] {item.get('url')} "
                    f"(handle={item.get('handle')}, confidence={item.get('confidence')})"
                )
            if len(found) > 15:
                print_info(f"  ... and {len(found) - 15} more")
        else:
            print_warning("No likely profile found for tested handles")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(data, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []

        target = data.get("target", "identity")
        nodes = []
        edges = []

        findings = data.get("findings", [])[:25]
        for idx, item in enumerate(findings):
            nid = f"profile_{idx}"
            label = f"@{item.get('handle')} on {item.get('platform')} ({item.get('confidence', 0)})"
            nodes.append({
                "id": nid,
                "label": label,
                "group": "hostname",
                "icon": "👤",
            })
            edges.append({
                "from": target,
                "to": nid,
                "label": "identity",
            })

        return nodes, edges
