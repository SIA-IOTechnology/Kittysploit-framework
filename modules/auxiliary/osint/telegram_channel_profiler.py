from kittysploit import *
import json
import re
from urllib.parse import quote

from core.osint.providers import telegram_bot_token
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Telegram Channel Profiler",
        "author": ["KittySploit Team"],
        "description": (
            "Passive Telegram surface profiling via public t.me previews and optional "
            "Bot API (getChat) for authorized investigations. No account login required."
        ),
        "tags": ["osint", "passive", "telegram", "social"],
    }

    target = OptString("", "Domain, @username, or channel slug to profile", required=True)
    bot_token = OptString("", "Optional Telegram Bot token (or set in ~/.kittysploit/osint.toml)", required=False)
    max_channels = OptString("15", "Maximum channel candidates to probe", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    BROWSER_UA = "Mozilla/5.0 (compatible; KittyOSINT/1.0; +https://kittysploit.local)"

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

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

    def _derive_candidates(self, raw_target):
        text = str(raw_target or "").strip().lower()
        text = re.sub(r"^https?://", "", text)
        text = text.lstrip("@").split("/", 1)[0]
        candidates = set()
        if not text:
            return []
        if text.startswith("t.me"):
            text = text.split("/", 1)[-1]
        candidates.add(text)
        if "." in text:
            apex = text.split(".", 1)[0]
            candidates.add(apex)
            candidates.add(f"{apex}news")
            candidates.add(f"{apex}_official")
            candidates.add(f"{apex}channel")
        else:
            candidates.add(f"{text}news")
            candidates.add(f"{text}_official")
        return sorted(candidates)

    def _parse_preview_html(self, html, slug):
        title = ""
        description = ""
        m = re.search(r'<meta property="og:title" content="([^"]+)"', html or "")
        if m:
            title = m.group(1)
        m = re.search(r'<meta property="og:description" content="([^"]+)"', html or "")
        if m:
            description = m.group(1)
        members = None
        m = re.search(r"([\d\s\u202f\u00a0.,]+)\s+members?", html or "", re.IGNORECASE)
        if m:
            digits = re.sub(r"[^\d]", "", m.group(1))
            if digits.isdigit():
                members = int(digits)
        return {
            "username": slug,
            "title": title,
            "description": description[:500] if description else "",
            "member_count": members,
            "url": f"https://t.me/s/{slug}",
            "platform": "telegram",
            "source": "t.me_preview",
            "confidence": 72 if title else 45,
        }

    def _fetch_preview(self, slug, timeout_seconds):
        path = f"/s/{quote(slug)}"
        resp = self._http_get_host(
            "t.me",
            path,
            timeout_seconds,
            headers={"User-Agent": self.BROWSER_UA},
        )
        if not resp or resp.status_code != 200:
            return None
        body = resp.text or ""
        if "tgme_page" not in body and "og:title" not in body:
            return None
        finding = self._parse_preview_html(body, slug)
        if not finding.get("title"):
            return None
        return finding

    def _fetch_bot_api(self, slug, token, timeout_seconds):
        if not token:
            return None
        chat_id = f"@{slug}" if not slug.startswith("@") else slug
        path = f"/bot{token}/getChat?chat_id={quote(chat_id)}"
        resp = self._http_get_host("api.telegram.org", path, timeout_seconds)
        if not resp or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        if not data.get("ok"):
            return None
        result = data.get("result") or {}
        username = str(result.get("username") or slug).lstrip("@")
        return {
            "username": username,
            "title": str(result.get("title") or ""),
            "description": str(result.get("description") or "")[:500],
            "member_count": result.get("member_count"),
            "url": f"https://t.me/{username}",
            "platform": "telegram",
            "source": "telegram_bot_api",
            "confidence": 88,
        }

    def run(self):
        candidates = self._derive_candidates(self.target)
        if not candidates:
            print_error("target must be a domain, @username, or channel slug")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 10)
        max_channels = self._to_int(self.max_channels, 15)
        token = telegram_bot_token(self.bot_token)

        print_info(f"Telegram profiling: {len(candidates)} candidate slug(s)")
        findings = []
        seen = set()

        for slug in candidates[:max_channels]:
            slug = slug.lstrip("@")
            if slug in seen:
                continue
            seen.add(slug)

            finding = None
            if token:
                finding = self._fetch_bot_api(slug, token, timeout_seconds)
            if not finding:
                finding = self._fetch_preview(slug, timeout_seconds)
            if finding:
                findings.append(finding)
                print_success(f"  @{finding.get('username')}: {finding.get('title', '')[:60]}")

        result = {
            "target": self.target,
            "findings": findings,
            "channel_count": len(findings),
            "bot_api_used": bool(token),
            "source_urls": [f.get("url") for f in findings if f.get("url")],
        }

        if not findings:
            print_warning("No public Telegram channels matched (try apex slug or @handle)")
        else:
            print_success(f"Telegram channels profiled: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return result
