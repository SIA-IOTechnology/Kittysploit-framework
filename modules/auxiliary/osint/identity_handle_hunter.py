from kittysploit import *
import json
import os
import re
from urllib.parse import urlparse

from core.osint.identity_handles import (
    API_VERIFIED_PLATFORMS,
    extract_handles,
    is_generic_handle,
    is_valid_handle_for_platform,
    normalize_profile_url,
)
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
    min_confidence = OptString("80", "Minimum confidence to keep a profile hit", required=False)
    skip_generic_handles = OptBool(True, "Reject generic mailbox usernames (info, admin, contact, …)", required=False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    # API-verified platforms only (no HTML scraping — too many false positives).
    PROFILE_PATTERNS = [
        ("github", "https://github.com/{handle}"),
        ("gitlab", "https://gitlab.com/{handle}"),
        ("reddit", "https://www.reddit.com/user/{handle}"),
        ("devto", "https://dev.to/{handle}"),
    ]

    BROWSER_UA = "Mozilla/5.0 (compatible; KittyOSINT/1.0; +https://kittysploit.local)"

    def _http_get_host(self, host, path, timeout_seconds, headers=None, ssl=True, port=443):
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = ssl
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
        return self._http_get_host(
            host,
            path,
            timeout_seconds,
            headers=headers,
            ssl=(scheme == "https"),
            port=port,
        )

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _extract_handles(self, query, query_type):
        if not self.skip_generic_handles:
            # Legacy path: keep old permissive extraction for explicit opt-out.
            handles = set()
            q = str(query).strip()
            qtype = str(query_type).strip().lower()
            if qtype == "email" and "@" in q:
                local = q.split("@", 1)[0]
                if local:
                    handles.add(local)
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
            return sorted(h for h in handles if len(h) >= 3)
        return extract_handles(query, query_type)

    def _not_found(self, http_status=None, title=""):
        return {"exists": False, "confidence": 0, "http_status": http_status, "title": title, "profile_url": ""}

    def _check_github(self, handle, timeout_seconds):
        headers = {"User-Agent": self.BROWSER_UA, "Accept": "application/vnd.github+json"}
        resp = self._http_get_host(
            "api.github.com",
            f"/users/{handle}",
            timeout_seconds,
            headers=headers,
        )
        if not resp:
            return self._not_found()
        if resp.status_code == 404:
            return self._not_found(404)
        if resp.status_code != 200:
            return self._not_found(resp.status_code)
        try:
            data = resp.json()
        except Exception:
            return self._not_found(resp.status_code)
        login = str(data.get("login", "")).lower()
        if login != handle.lower():
            return self._not_found(resp.status_code)
        return {
            "exists": True,
            "confidence": 88,
            "http_status": resp.status_code,
            "title": str(data.get("name") or data.get("login") or ""),
            "profile_url": str(data.get("html_url") or f"https://github.com/{handle}"),
        }

    def _check_gitlab(self, handle, timeout_seconds):
        path = f"/api/v4/users?username={handle}"
        resp = self._http_get_host("gitlab.com", path, timeout_seconds, headers={"User-Agent": self.BROWSER_UA})
        if not resp:
            return self._not_found()
        if resp.status_code != 200:
            return self._not_found(resp.status_code)
        try:
            rows = resp.json()
        except Exception:
            return self._not_found(resp.status_code)
        if not isinstance(rows, list) or not rows:
            return self._not_found(200)
        user = rows[0]
        if str(user.get("username", "")).lower() != handle.lower():
            return self._not_found(200)
        return {
            "exists": True,
            "confidence": 86,
            "http_status": 200,
            "title": str(user.get("name") or user.get("username") or ""),
            "profile_url": str(user.get("web_url") or f"https://gitlab.com/{handle}"),
        }

    def _parse_reddit_about(self, resp, handle):
        if resp.status_code == 404:
            return self._not_found(404)
        if resp.status_code != 200:
            return self._not_found(resp.status_code)
        try:
            payload = resp.json()
        except Exception:
            return self._not_found(resp.status_code)
        if not isinstance(payload, dict):
            return self._not_found(resp.status_code)
        if payload.get("error"):
            return self._not_found(resp.status_code, str(payload.get("message") or ""))
        data = payload.get("data")
        if not isinstance(data, dict) or not data.get("id"):
            return self._not_found(resp.status_code)
        name = str(data.get("name") or "")
        if name.lower() != handle.lower():
            return self._not_found(resp.status_code)
        return {
            "exists": True,
            "confidence": 84,
            "http_status": resp.status_code,
            "title": name,
            "profile_url": f"https://www.reddit.com/user/{name}/",
        }

    def _check_reddit(self, handle, timeout_seconds):
        headers = {"User-Agent": self.BROWSER_UA}
        for host in ("www.reddit.com", "old.reddit.com"):
            path = f"/user/{handle}/about.json"
            resp = self._http_get_host(host, path, timeout_seconds, headers=headers)
            if not resp:
                continue
            meta = self._parse_reddit_about(resp, handle)
            if meta.get("exists"):
                return meta
            if resp.status_code in (404, 403):
                return meta
        return self._not_found()

    def _check_devto(self, handle, timeout_seconds):
        path = f"/api/users/by_username?url={handle}"
        headers = {"User-Agent": self.BROWSER_UA, "Accept": "application/json"}
        resp = self._http_get_host("dev.to", path, timeout_seconds, headers=headers)
        if not resp:
            return self._not_found()
        if resp.status_code == 404:
            return self._not_found(404)
        if resp.status_code != 200:
            return self._not_found(resp.status_code)
        try:
            data = resp.json()
        except Exception:
            return self._not_found(resp.status_code)
        username = str((data or {}).get("username") or "").lower()
        if username != handle.lower():
            return self._not_found(resp.status_code)
        return {
            "exists": True,
            "confidence": 82,
            "http_status": resp.status_code,
            "title": str(data.get("name") or data.get("username") or ""),
            "profile_url": f"https://dev.to/{data.get('username', handle)}",
        }

    def _check_profile_url(self, platform, url, handle, timeout_seconds):
        if platform not in API_VERIFIED_PLATFORMS:
            return {
                "platform": platform,
                "url": normalize_profile_url(url),
                "http_status": None,
                "exists": False,
                "confidence": 0,
                "title": "",
            }

        api_checkers = {
            "github": self._check_github,
            "gitlab": self._check_gitlab,
            "reddit": self._check_reddit,
            "devto": self._check_devto,
        }
        checker = api_checkers.get(platform)
        try:
            meta = checker(handle, timeout_seconds) if checker else self._not_found()
            profile_url = normalize_profile_url(meta.get("profile_url") or url)
            return {
                "platform": platform,
                "url": profile_url,
                "http_status": meta.get("http_status"),
                "exists": bool(meta.get("exists")),
                "confidence": int(meta.get("confidence") or 0),
                "title": meta.get("title") or "",
            }
        except Exception as e:
            return {
                "platform": platform,
                "url": normalize_profile_url(url),
                "http_status": None,
                "exists": False,
                "confidence": 0,
                "title": "",
                "error": str(e),
            }

    def run(self):
        query = str(self.query).strip()
        query_type = str(self.query_type).strip().lower() or "username"
        timeout_seconds = self._to_int(self.timeout, 8)
        max_results = self._to_int(self.max_results, 30)
        min_confidence = min(100, self._to_int(self.min_confidence, 70))

        if not query:
            print_warning("No identity query provided; skipping profile discovery")
            return {
                "target": "",
                "query_type": query_type,
                "skipped": True,
                "reason": "empty_query",
                "handles_tested": [],
                "count": 0,
                "findings": [],
            }

        if query_type not in ("username", "email", "name"):
            print_warning(f"Unknown query_type '{query_type}', fallback to 'username'")
            query_type = "username"

        if query_type == "email" and "@" in query:
            local = query.split("@", 1)[0].strip().lower()
            if self.skip_generic_handles and is_generic_handle(local):
                print_warning(
                    f"Mailbox local-part '{local}' is too generic for profile attribution; "
                    "provide a person name or distinctive username instead"
                )
                return {
                    "target": query,
                    "query_type": query_type,
                    "skipped": True,
                    "reason": "generic_mailbox_local_part",
                    "handles_tested": [],
                    "count": 0,
                    "findings": [],
                }

        handles = self._extract_handles(query, query_type)
        if not handles:
            print_warning("No distinctive handle could be derived from query (generic or empty)")
            return {
                "target": query,
                "query_type": query_type,
                "skipped": True,
                "reason": "no_distinctive_handle",
                "handles_tested": [],
                "count": 0,
                "findings": [],
            }

        print_info(f"Target query: {query} ({query_type})")
        print_info(f"Generated {len(handles)} handle candidate(s): {', '.join(handles[:5])}")

        results = []
        for handle in handles:
            for platform, pattern in self.PROFILE_PATTERNS:
                if not is_valid_handle_for_platform(handle, platform):
                    continue
                url = pattern.format(handle=handle)
                entry = self._check_profile_url(platform, url, handle, timeout_seconds)
                entry["handle"] = handle
                if entry.get("exists") and entry.get("confidence", 0) >= min_confidence:
                    results.append(entry)

        unique = {}
        for item in results:
            key = (item.get("platform"), item.get("handle"))
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
                parent = os.path.dirname(str(self.output_file))
                if parent:
                    os.makedirs(parent, exist_ok=True)
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
