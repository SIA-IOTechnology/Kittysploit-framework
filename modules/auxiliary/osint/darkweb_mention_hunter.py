from kittysploit import *
import json
import re
import time
from urllib.parse import urlparse

from core.osint.providers import intelx_api_key
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Dark Web Mention Hunter",
        "author": ["KittySploit Team"],
        "description": (
            "Search authorized breach/darkweb intelligence providers (IntelX API) for "
            "mentions of a domain, email, or keyword. Does not perform direct Tor scraping."
        ),
        "tags": ["osint", "passive", "darkweb", "breach", "le"],
    }

    target = OptString("", "Domain, email, or keyword to search", required=True)
    intelx_key = OptString("", "IntelX API key (or set in ~/.kittysploit/osint.toml)", required=False)
    max_results = OptString("25", "Maximum findings to keep", required=False)
    timeout = OptString("15", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    INTELX_SEARCH_URL = "https://2.intelx.io/intelligent/search"
    INTELX_RESULT_URL = "https://2.intelx.io/intelligent/search/result"
    DARKWEB_BUCKETS = ("darknet", "leaks.public", "dumpster", "pastes")

    def _http_post_json_url(self, url, payload, timeout_seconds, headers=None):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = 443
            self.ssl = True
            return self.http_request(
                method="POST",
                path=path,
                timeout=timeout_seconds,
                headers=headers or {},
                data=json.dumps(payload),
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
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        old_target = self.target
        try:
            self.target = host
            self.port = 443
            self.ssl = True
            return self.http_request(
                method="GET",
                path=path,
                timeout=timeout_seconds,
                headers=headers or {},
            )
        except Exception:
            return None
        finally:
            self.target = old_target

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_target(self, value):
        text = str(value or "").strip().lower()
        text = re.sub(r"^https?://", "", text)
        text = text.split("/", 1)[0].strip(".")
        if not text or len(text) < 3:
            return None
        return text

    def _intelx_headers(self, api_key):
        return {
            "User-Agent": "KittyOSINT/1.0",
            "Content-Type": "application/json",
            "x-key": api_key,
        }

    def _start_search(self, term, api_key, timeout_seconds):
        payload = {
            "term": term,
            "buckets": list(self.DARKWEB_BUCKETS),
            "lookuplevel": 0,
            "maxresults": 30,
            "timeout": max(3, timeout_seconds),
            "sort": 2,
            "media": 0,
        }
        resp = self._http_post_json_url(
            self.INTELX_SEARCH_URL,
            payload,
            timeout_seconds,
            self._intelx_headers(api_key),
        )
        if not resp or resp.status_code not in (200, 201):
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        return str(data.get("id") or "")

    def _poll_results(self, search_id, api_key, timeout_seconds, max_results):
        findings = []
        headers = self._intelx_headers(api_key)
        deadline = time.time() + timeout_seconds
        while time.time() < deadline and len(findings) < max_results:
            url = f"{self.INTELX_RESULT_URL}?id={search_id}&limit=20"
            resp = self._http_get_url(url, min(8, timeout_seconds), headers)
            if not resp or resp.status_code != 200:
                break
            try:
                data = resp.json()
            except Exception:
                break
            records = data.get("records") or []
            if not records and data.get("status") == 2:
                break
            for row in records:
                if not isinstance(row, dict):
                    continue
                bucket = str(row.get("bucket") or row.get("source") or "unknown")
                name = str(row.get("name") or row.get("title") or "")[:256]
                snippet = str(row.get("snippet") or row.get("text") or name)[:512]
                findings.append({
                    "title": name,
                    "snippet": snippet,
                    "bucket": bucket,
                    "source": "intelx",
                    "media": row.get("media"),
                    "date": row.get("date") or row.get("added"),
                    "confidence": 70 if bucket in self.DARKWEB_BUCKETS else 55,
                })
                if len(findings) >= max_results:
                    break
            if data.get("status") == 2:
                break
            time.sleep(1.2)
        return findings

    def run(self):
        term = self._normalize_target(self.target)
        if not term:
            print_error("Invalid target — provide domain, email, or keyword")
            return {"error": "invalid target"}

        api_key = intelx_api_key(self.intelx_key)
        timeout_seconds = self._to_int(self.timeout, 15)
        max_results = self._to_int(self.max_results, 25)

        if not api_key:
            print_warning(
                "IntelX API key not configured — set providers.intelx.api_key in osint.toml or intelx_key option"
            )
            return {
                "target": term,
                "skipped": True,
                "reason": "intelx_api_key_required",
                "findings": [],
                "provider": "intelx",
            }

        print_info(f"Darkweb mention search (IntelX provider) for: {term}")
        search_id = self._start_search(term, api_key, timeout_seconds)
        if not search_id:
            print_warning("IntelX search did not start (rate limit, key, or network)")
            return {
                "target": term,
                "findings": [],
                "error": "intelx_search_failed",
                "provider": "intelx",
            }

        findings = self._poll_results(search_id, api_key, timeout_seconds, max_results)
        risk_score = min(100, len(findings) * 8)

        result = {
            "target": term,
            "findings": findings,
            "mention_count": len(findings),
            "risk_score": risk_score,
            "provider": "intelx",
            "search_id": search_id,
            "source_urls": [self.INTELX_SEARCH_URL],
        }

        if findings:
            print_success(f"Darkweb/breach mentions: {len(findings)} (risk={risk_score})")
        else:
            print_info("No darkweb mentions returned for this term")

        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return result
