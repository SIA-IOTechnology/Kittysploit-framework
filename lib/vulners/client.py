"""HTTP client for the Vulners API (v3 search + v4 references/audit)."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

import requests

PLUGIN_VERSION = "1.1.0"
BASE_URL = "https://vulners.com"

LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene"
SEARCH_ID_URL = f"{BASE_URL}/api/v3/search/id"
REFERENCES_URL = f"{BASE_URL}/api/v4/search/references"
LINUX_AUDIT_URL = f"{BASE_URL}/api/v4/audit/linux"
LIBRARY_AUDIT_URL = f"{BASE_URL}/api/v4/audit/library"

DEFAULT_SEARCH_FIELDS = [
    "id",
    "title",
    "description",
    "published",
    "modified",
    "type",
    "bulletinFamily",
    "cvelist",
    "href",
    "cvss",
    "enchantments",
    "sourceData",
]

REFERENCE_FIELDS = [
    "id",
    "title",
    "type",
    "bulletinFamily",
    "href",
    "published",
    "modified",
    "cvelist",
    "enchantments",
]


class VulnersError(RuntimeError):
    """Raised when the Vulners API returns an error response."""


def normalize_bulletin(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    if "_source" in raw and isinstance(raw["_source"], dict):
        item = dict(raw["_source"])
        item.setdefault("id", raw.get("_id") or item.get("id"))
        return item
    return dict(raw)


def bulletin_display_title(doc: Dict[str, Any]) -> str:
    """Prefer enchantments.short_description for CVE rows (avoid duplicate id/title)."""
    doc_id = str(doc.get("id") or "").strip()
    title = str(doc.get("title") or "").strip()
    enchant = doc.get("enchantments")
    short = ""
    if isinstance(enchant, dict):
        short = str(enchant.get("short_description") or "").strip()
    if doc_id.upper().startswith("CVE-") and title.upper() == doc_id.upper() and short:
        return short
    if title:
        return title
    return short or doc_id


def exploits_query_for_cves(cves: Sequence[str]) -> str:
    tokens = sorted({str(c).strip().upper() for c in cves if str(c).strip()})
    if not tokens:
        return ""
    if len(tokens) == 1:
        return f"bulletinFamily:exploit AND cvelist:{tokens[0]}"
    joined = " OR ".join(tokens)
    return f"bulletinFamily:exploit AND cvelist:({joined})"


class VulnersClient:
    def __init__(
        self,
        api_key: str,
        *,
        min_interval_s: float = 0.25,
        timeout_s: float = 120.0,
    ) -> None:
        key = str(api_key or "").strip()
        if not key:
            raise VulnersError("Vulners API key is required")
        self.api_key = key
        self.min_interval_s = min_interval_s
        self.timeout_s = timeout_s
        self._last_request = 0.0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Api-Key": key,
                "Content-Type": "application/json",
                "User-Agent": f"KittySploit-Vulners-Plugin/{PLUGIN_VERSION}",
            }
        )

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval_s:
            time.sleep(self.min_interval_s - elapsed)

    def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        accept_partial: bool = False,
    ) -> Dict[str, Any]:
        self._throttle()
        response = self.session.request(
            method,
            url,
            json=json_body,
            params=params,
            timeout=self.timeout_s,
        )
        self._last_request = time.monotonic()
        if accept_partial and response.status_code in (200, 206):
            pass
        elif not response.ok:
            detail = response.text[:500]
            raise VulnersError(f"Vulners HTTP {response.status_code}: {detail}")
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise VulnersError(f"Invalid JSON from Vulners: {exc}") from exc
        if isinstance(payload, dict) and payload.get("result") == "error":
            raise VulnersError(str(payload.get("data") or payload))
        return payload if isinstance(payload, dict) else {"data": payload}

    @staticmethod
    def _unwrap_data(payload: Dict[str, Any]) -> Any:
        if "data" in payload:
            return payload["data"]
        if "result" in payload:
            return payload["result"]
        return payload

    def search_lucene_page(
        self,
        query: str,
        *,
        skip: int = 0,
        size: int = 20,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "query": query,
            "skip": max(0, int(skip)),
            "size": max(1, min(int(size), 100)),
            "fields": fields or DEFAULT_SEARCH_FIELDS,
        }
        payload = self._request("POST", LUCENE_URL, json_body=body)
        data = self._unwrap_data(payload)
        if isinstance(data, dict):
            return data
        return {"search": data or [], "total": len(data or [])}

    def max_search_size(self, query: str) -> int:
        page = self.search_lucene_page(query, skip=0, size=1)
        try:
            return max(1, min(int(page.get("maxSearchSize") or 100), 100))
        except (TypeError, ValueError):
            return 100

    def iter_search(
        self,
        query: str,
        *,
        limit: int = 20,
        fields: Optional[List[str]] = None,
    ) -> Iterator[Dict[str, Any]]:
        remaining = max(0, int(limit))
        skip = 0
        page_size = min(100, remaining) if remaining else 100
        if remaining:
            page_size = min(page_size, self.max_search_size(query))
        while remaining > 0:
            size = min(page_size, remaining)
            page = self.search_lucene_page(query, skip=skip, size=size, fields=fields)
            items = page.get("search") or []
            if not items:
                break
            for item in items:
                yield normalize_bulletin(item)
                remaining -= 1
                if remaining <= 0:
                    return
            skip += len(items)
            total = int(page.get("total") or 0)
            if skip >= total or len(items) < size:
                break

    def search_by_id(
        self,
        bulletin_id: Union[str, Sequence[str]],
        *,
        references: bool = False,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ids = [bulletin_id] if isinstance(bulletin_id, str) else list(bulletin_id)
        body: Dict[str, Any] = {
            "id": ids[0] if len(ids) == 1 else ids,
            "fields": fields or DEFAULT_SEARCH_FIELDS,
        }
        if references:
            body["references"] = True
            body["referenceFields"] = REFERENCE_FIELDS
        payload = self._request(
            "POST",
            SEARCH_ID_URL,
            json_body=body,
            accept_partial=references,
        )
        return self._unwrap_data(payload)

    def iter_references(
        self,
        bulletin_id: str,
        *,
        ref_type: Optional[str] = None,
        page_size: int = 100,
        fields: Optional[List[str]] = None,
    ) -> Iterator[Dict[str, Any]]:
        skip = 0
        size = max(1, min(int(page_size), 100))
        params_base: Dict[str, Any] = {"id": bulletin_id, "size": size}
        if ref_type:
            params_base["type"] = ref_type
        if fields:
            params_base["fields"] = json.dumps(list(fields))

        while True:
            params = dict(params_base)
            params["skip"] = skip
            payload = self._request("GET", REFERENCES_URL, params=params)
            result = self._unwrap_data(payload)
            if not isinstance(result, dict):
                break
            buckets = result.get("references") or {}
            if not isinstance(buckets, dict):
                break
            page_count = 0
            for _collection, items in buckets.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict) and item.get("missing"):
                        continue
                    if isinstance(item, dict):
                        yield normalize_bulletin(item)
                        page_count += 1
            if page_count < size:
                break
            skip += page_count
            total = int(result.get("total") or 0)
            if skip >= total:
                break

    def fetch_public_exploits(
        self,
        cves: Sequence[str],
        *,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        query = exploits_query_for_cves(cves)
        if not query:
            return []
        return list(self.iter_search(query, limit=limit))

    def linux_audit(
        self,
        os_name: str,
        os_version: str,
        packages: Sequence[str],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "osName": os_name,
            "osVersion": os_version,
            "packages": list(packages),
        }
        for key, value in kwargs.items():
            if value is not None:
                body[key] = value
        payload = self._request("POST", LINUX_AUDIT_URL, json_body=body)
        data = self._unwrap_data(payload)
        return data if isinstance(data, dict) else {"data": data}

    def library_audit(self, packages: Sequence[str], **kwargs: Any) -> Dict[str, Any]:
        body: Dict[str, Any] = {"packages": list(packages)}
        for key, value in kwargs.items():
            if value is not None:
                body[key] = value
        payload = self._request("POST", LIBRARY_AUDIT_URL, json_body=body)
        data = self._unwrap_data(payload)
        return data if isinstance(data, dict) else {"data": data}
