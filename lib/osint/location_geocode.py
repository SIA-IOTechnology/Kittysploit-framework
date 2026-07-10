#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Free-text location normalization via Nominatim (OpenStreetMap) with file cache."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import aiohttp

from core.osint.config import get_osint_config

NOMINATIM_SEARCH_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = "KittyOSINT-LocationGeocode/1.0 (authorized OSINT)"
MIN_REQUEST_INTERVAL_SECONDS = 1.1
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60

_last_upstream_request_at: float = 0.0
_memory_cache: dict[str, tuple[float, dict[str, Any]]] = {}


@dataclass
class GeocodeResolution:
    query: str
    display_name: str = ""
    lat: float | None = None
    lon: float | None = None
    country: str = ""
    region: str = ""
    city: str = ""
    postcode: str = ""
    confidence: float = 0.0
    cache_hit: bool = False
    rate_limited: bool = False
    retry_after_seconds: int | None = None
    error: str = ""
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["properties"] = dict(self.properties)
        return payload


def _cache_path() -> Path | None:
    try:
        audit_dir = Path(get_osint_config().audit_dir())
        audit_dir.mkdir(parents=True, exist_ok=True)
        return audit_dir / "geocode_cache.json"
    except OSError:
        return None


def _normalize_cache_key(query: str) -> str:
    return " ".join(str(query or "").strip().lower().split())


def _load_disk_cache() -> dict[str, Any]:
    path = _cache_path()
    if path is None or not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_disk_cache(cache: dict[str, Any]) -> None:
    path = _cache_path()
    if path is None:
        return
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(cache, handle, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _get_cached_entry(query: str, *, use_cache: bool) -> dict[str, Any] | None:
    if not use_cache:
        return None
    key = _normalize_cache_key(query)
    now = time.time()

    mem = _memory_cache.get(key)
    if mem and (now - mem[0]) < CACHE_TTL_SECONDS:
        return mem[1]

    disk = _load_disk_cache().get(key)
    if not isinstance(disk, dict):
        return None
    cached_at = float(disk.get("cached_at", 0) or 0)
    if cached_at and (now - cached_at) >= CACHE_TTL_SECONDS:
        return None
    entry = disk.get("resolution")
    if isinstance(entry, dict):
        _memory_cache[key] = (now, entry)
        return entry
    return None


def _store_cached_entry(query: str, resolution: GeocodeResolution) -> None:
    key = _normalize_cache_key(query)
    now = time.time()
    payload = {
        "cached_at": now,
        "resolution": {
            "display_name": resolution.display_name,
            "lat": resolution.lat,
            "lon": resolution.lon,
            "country": resolution.country,
            "region": resolution.region,
            "city": resolution.city,
            "postcode": resolution.postcode,
            "confidence": resolution.confidence,
            "properties": resolution.properties,
        },
    }
    _memory_cache[key] = (now, payload["resolution"])
    cache = _load_disk_cache()
    cache[key] = payload
    _save_disk_cache(cache)


def _extract_address_field(address: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = address.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _parse_nominatim_result(query: str, row: dict[str, Any]) -> GeocodeResolution:
    address = row.get("address") if isinstance(row.get("address"), dict) else {}
    display_name = str(row.get("display_name") or query).strip() or query
    try:
        lat = float(row.get("lat"))
        lon = float(row.get("lon"))
    except (TypeError, ValueError):
        lat = None
        lon = None

    confidence = 0.0
    try:
        confidence = float(row.get("importance") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0

    country = _extract_address_field(address, "country")
    region = _extract_address_field(address, "state", "region", "county", "state_district")
    city = _extract_address_field(
        address,
        "city",
        "town",
        "village",
        "municipality",
        "hamlet",
        "suburb",
        "locality",
    )
    postcode = _extract_address_field(address, "postcode")

    properties = {
        "lat": lat,
        "lon": lon,
        "location_label": display_name,
        "geo_confidence": round(confidence, 4),
    }
    if country:
        properties["country"] = country
    if region:
        properties["region"] = region
        properties["state"] = region
    if city:
        properties["city"] = city
    if postcode:
        properties["postcode"] = postcode
    if row.get("place_id") is not None:
        properties["place_id"] = row.get("place_id")
    if row.get("osm_type"):
        properties["osm_type"] = row.get("osm_type")
    if row.get("osm_id") is not None:
        properties["osm_id"] = row.get("osm_id")

    return GeocodeResolution(
        query=query,
        display_name=display_name,
        lat=lat,
        lon=lon,
        country=country,
        region=region,
        city=city,
        postcode=postcode,
        confidence=confidence,
        properties=properties,
    )


async def normalize_location(
    query: str,
    *,
    use_cache: bool = True,
    timeout_seconds: float = 10.0,
) -> GeocodeResolution:
    """Normalize a free-text location into coordinates and admin fields."""
    global _last_upstream_request_at

    text = str(query or "").strip()
    if not text:
        return GeocodeResolution(query="", error="empty_query")

    cached = _get_cached_entry(text, use_cache=use_cache)
    if cached:
        return GeocodeResolution(
            query=text,
            display_name=str(cached.get("display_name") or text),
            lat=cached.get("lat"),
            lon=cached.get("lon"),
            country=str(cached.get("country") or ""),
            region=str(cached.get("region") or ""),
            city=str(cached.get("city") or ""),
            postcode=str(cached.get("postcode") or ""),
            confidence=float(cached.get("confidence") or 0.0),
            cache_hit=True,
            properties=dict(cached.get("properties") or {}),
        )

    now = time.time()
    elapsed = now - _last_upstream_request_at
    if elapsed < MIN_REQUEST_INTERVAL_SECONDS:
        retry_after = max(1, int(MIN_REQUEST_INTERVAL_SECONDS - elapsed) + 1)
        return GeocodeResolution(
            query=text,
            rate_limited=True,
            retry_after_seconds=retry_after,
            error="rate_limited",
        )

    params = {
        "q": text,
        "format": "jsonv2",
        "addressdetails": "1",
        "limit": "1",
    }
    url = f"{NOMINATIM_SEARCH_URL}?{ '&'.join(f'{k}={quote(str(v))}' for k, v in params.items()) }"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as response:
                _last_upstream_request_at = time.time()
                if response.status == 429:
                    retry_after = int(response.headers.get("Retry-After", "60") or 60)
                    return GeocodeResolution(
                        query=text,
                        rate_limited=True,
                        retry_after_seconds=retry_after,
                        error="upstream_rate_limited",
                    )
                if response.status != 200:
                    return GeocodeResolution(
                        query=text,
                        error=f"HTTP {response.status}",
                    )
                payload = await response.json(content_type=None)
    except asyncio.TimeoutError:
        return GeocodeResolution(query=text, error="request_timed_out")
    except aiohttp.ClientError as exc:
        return GeocodeResolution(query=text, error=f"request_error: {exc}")

    if not isinstance(payload, list) or not payload:
        return GeocodeResolution(query=text, error="no_results")

    row = payload[0] if isinstance(payload[0], dict) else {}
    resolution = _parse_nominatim_result(text, row)
    if resolution.lat is None or resolution.lon is None:
        return GeocodeResolution(query=text, error="missing_coordinates")

    if use_cache:
        _store_cached_entry(text, resolution)
    return resolution


def normalize_location_sync(query: str, **kwargs: Any) -> GeocodeResolution:
    """Synchronous wrapper for location normalization."""
    return asyncio.run(normalize_location(query, **kwargs))
