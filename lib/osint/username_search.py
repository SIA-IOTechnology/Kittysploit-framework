#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WhatsMyName-backed username enumeration across social platforms."""

from __future__ import annotations

import asyncio
import random
import string
import time
from typing import Any

import aiohttp

from core.osint.identity_handles import is_generic_handle

WHATS_MY_NAME_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CATALOG_TTL_SECONDS = 24 * 60 * 60
SITE_VALIDATION_TTL_SECONDS = 72 * 60 * 60
USER_AGENT = "KittyOSINT-UsernameSearch/1.0"

FALLBACK_PLATFORMS: list[dict[str, Any]] = [
    {
        "name": "GitHub",
        "cat": "developer",
        "uri_check": "https://github.com/{account}",
        "uri_pretty": "https://github.com/{account}",
        "e_code": 200,
        "e_string": "",
        "must_have_name": True,
    },
    {
        "name": "Reddit",
        "cat": "community",
        "uri_check": "https://www.reddit.com/user/{account}",
        "uri_pretty": "https://www.reddit.com/user/{account}",
        "e_code": 200,
        "e_string": "",
        "must_have_name": True,
    },
    {
        "name": "Keybase",
        "cat": "developer",
        "uri_check": "https://keybase.io/{account}",
        "uri_pretty": "https://keybase.io/{account}",
        "e_code": 200,
        "e_string": "",
        "must_have_name": True,
    },
]

_catalog_cache: tuple[float, list[dict[str, Any]]] | None = None
_trusted_sites_cache: tuple[float, list[dict[str, Any]]] | None = None


def generate_permutations(username: str) -> list[str]:
    """Bounded typo/separator variations for a username."""
    permutations: set[str] = set()
    replacements = {
        "a": ["4"],
        "e": ["3"],
        "i": ["1"],
        "l": ["1"],
        "o": ["0"],
        "s": ["5"],
        "t": ["7"],
    }
    separators = ["_", "-"]

    for idx, char in enumerate(username.lower()):
        for repl in replacements.get(char, []):
            permutations.add(username[:idx] + repl + username[idx + 1 :])

    for separator in separators:
        permutations.add(f"{username}{separator}")
        permutations.add(f"{separator}{username}")

    if "." not in username and len(username) >= 6:
        midpoint = len(username) // 2
        permutations.add(username[:midpoint] + "." + username[midpoint:])

    return [value for value in permutations if value != username and len(value) >= 4]


def _random_probe_username() -> str:
    rand = random.SystemRandom()
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rand.choice(alphabet) for _ in range(12))


def _not_found(site: dict[str, Any], username: str, reason: str) -> dict[str, Any]:
    return {
        "found": False,
        "platform_name": str(site.get("name", "Unknown")),
        "site_category": str(site.get("cat", "general")),
        "matched_username": username,
        "profile_url": "",
        "reason": reason,
    }


async def _load_site_catalog() -> tuple[list[dict[str, Any]], str]:
    global _catalog_cache
    now = time.time()
    if _catalog_cache and (now - _catalog_cache[0]) < CATALOG_TTL_SECONDS:
        return _catalog_cache[1], "cache"

    try:
        timeout = aiohttp.ClientTimeout(total=8.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(WHATS_MY_NAME_URL) as response:
                response.raise_for_status()
                payload = await response.json(content_type=None)
        sites = [
            site
            for site in payload.get("sites", [])
            if site.get("valid", True) is not False and site.get("uri_check")
        ]
        if sites:
            _catalog_cache = (now, sites)
            return sites, "whatsmyname"
    except Exception:
        pass

    _catalog_cache = (now, FALLBACK_PLATFORMS)
    return FALLBACK_PLATFORMS, "fallback"


async def _check_site(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    username: str,
    site: dict[str, Any],
    must_have_name: bool,
) -> dict[str, Any]:
    async with sem:
        template = site.get("uri_check")
        if not isinstance(template, str) or "{account}" not in template:
            return _not_found(site, username, "unsupported site definition")

        profile_url = template.format(account=username)
        pretty_url = site.get("uri_pretty", profile_url)
        post_body = site.get("post_body")
        method = "POST" if post_body else "GET"

        try:
            async with session.request(
                method,
                profile_url,
                data=post_body if post_body else None,
                allow_redirects=True,
            ) as response:
                status_code = response.status
                body = await response.text(errors="replace")
        except asyncio.TimeoutError:
            return _not_found(site, username, "request timed out")
        except aiohttp.ClientError as exc:
            return _not_found(site, username, f"request error: {exc}")

        expected_code = site.get("e_code")
        if expected_code is not None and str(status_code) != str(expected_code):
            return _not_found(site, username, f"HTTP {status_code}")

        expected_text = site.get("e_string")
        missing_text = site.get("m_string")

        if expected_text and expected_text not in body:
            return _not_found(site, username, "match string missing")
        if missing_text and missing_text in body:
            return _not_found(site, username, "missing-string marker present")
        if must_have_name and username.lower() not in body.lower():
            return _not_found(site, username, "username absent from page content")
        if "." in username:
            first = username.split(".", 1)[0]
            lowered = body.lower()
            if f"{first}<" in lowered or f'{first}"' in lowered:
                return _not_found(site, username, "dot-username false-positive guard")

        return {
            "found": True,
            "platform_name": str(site.get("name", "Unknown")),
            "site_category": str(site.get("cat", "general")),
            "matched_username": username,
            "profile_url": pretty_url.format(account=username) if isinstance(pretty_url, str) else profile_url,
        }


async def _scan_candidates(
    *,
    candidates: list[str],
    sites: list[dict[str, Any]],
    concurrency: int,
    must_have_name: bool,
    timeout_seconds: float = 6.0,
) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    headers = {"User-Agent": USER_AGENT}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [
            _check_site(session, sem, candidate, site, must_have_name)
            for candidate in candidates
            for site in sites
        ]
        return await asyncio.gather(*tasks)


async def _filter_untrusted_sites(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    global _trusted_sites_cache
    now = time.time()
    if _trusted_sites_cache and (now - _trusted_sites_cache[0]) < SITE_VALIDATION_TTL_SECONDS:
        return _trusted_sites_cache[1]

    probe = _random_probe_username()
    results = await _scan_candidates(
        candidates=[probe],
        sites=sites[: min(len(sites), 40)],
        concurrency=8,
        must_have_name=True,
    )
    distrusted = {item["platform_name"] for item in results if item["found"]}
    trusted = [site for site in sites if site.get("name") not in distrusted]
    _trusted_sites_cache = (now, trusted)
    return trusted


async def _get_candidate_sites(max_sites: int) -> tuple[list[dict[str, Any]], str]:
    sites, source = await _load_site_catalog()
    trusted = await _filter_untrusted_sites(sites)
    return trusted[:max_sites], source


async def search_username_accounts(
    username: str,
    *,
    min_username_length: int = 4,
    must_have_name: bool = True,
    scan_permutations: bool = False,
    max_sites: int = 25,
    concurrency: int = 10,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Scan social platforms for username presence using the WhatsMyName catalog."""
    username = str(username or "").strip()
    if not username:
        return {
            "username": "",
            "skipped": True,
            "reason": "empty_username",
            "messages": ["No username value available for scanning."],
            "catalog_source": "",
            "candidates_tested": [],
            "sites_scanned": 0,
            "count": 0,
            "findings": [],
        }

    if len(username) < min_username_length:
        return {
            "username": username,
            "skipped": True,
            "reason": "below_min_length",
            "messages": [f"Skipped '{username}': below minimum username length {min_username_length}."],
            "catalog_source": "",
            "candidates_tested": [],
            "sites_scanned": 0,
            "count": 0,
            "findings": [],
        }

    if is_generic_handle(username):
        return {
            "username": username,
            "skipped": True,
            "reason": "generic_username",
            "messages": [f"Skipped '{username}': too generic for reliable account search."],
            "catalog_source": "",
            "candidates_tested": [],
            "sites_scanned": 0,
            "count": 0,
            "findings": [],
        }

    candidates = [username]
    if scan_permutations:
        candidates.extend(generate_permutations(username))
    candidates = list(dict.fromkeys(candidates))[:6]

    sites, catalog_source = await _get_candidate_sites(max_sites=max_sites)
    if not sites:
        return {
            "username": username,
            "skipped": True,
            "reason": "no_catalog",
            "messages": ["No site catalog available for username search."],
            "catalog_source": catalog_source,
            "candidates_tested": candidates,
            "sites_scanned": 0,
            "count": 0,
            "findings": [],
        }

    messages = [
        f"Scanning {len(candidates)} username candidate(s) across {len(sites)} site(s) from {catalog_source}."
    ]
    results = await _scan_candidates(
        candidates=candidates,
        sites=sites,
        concurrency=concurrency,
        must_have_name=must_have_name,
        timeout_seconds=timeout_seconds,
    )

    seen_social: set[str] = set()
    findings: list[dict[str, Any]] = []
    for result in results:
        if not result.get("found"):
            continue
        matched_username = result["matched_username"]
        platform_name = result["platform_name"]
        profile_url = result["profile_url"]
        social_key = f"{matched_username}@{platform_name}"
        if social_key in seen_social:
            continue
        seen_social.add(social_key)
        findings.append({
            "platform": platform_name,
            "username": matched_username,
            "profile_url": profile_url,
            "site_category": result.get("site_category", "general"),
            "account_match": "exact" if matched_username == username else "similar",
        })
        messages.append(f"Found {platform_name} account for {matched_username}: {profile_url}")

    if not findings:
        messages.append("No matching accounts found in the scanned site set.")

    return {
        "username": username,
        "skipped": False,
        "reason": "",
        "messages": messages,
        "catalog_source": catalog_source,
        "candidates_tested": candidates,
        "sites_scanned": len(sites),
        "count": len(findings),
        "findings": findings,
    }


def search_username_accounts_sync(username: str, **kwargs: Any) -> dict[str, Any]:
    """Synchronous wrapper for username account search."""
    return asyncio.run(search_username_accounts(username, **kwargs))
