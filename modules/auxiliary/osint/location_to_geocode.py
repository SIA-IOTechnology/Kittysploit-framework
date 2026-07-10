#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize a free-text location into coordinates and administrative fields."""

from __future__ import annotations

import json
import os

from kittysploit import *

from lib.osint.location_geocode import normalize_location_sync


class Module(Auxiliary):
    __info__ = {
        "name": "Location to Geocode",
        "author": ["KittySploit Team"],
        "description": (
            "Normalize a free-text location into canonical coordinates, "
            "display label, and country/region/city/postcode fields (Nominatim)."
        ),
        "tags": ["osint", "location", "geocode", "passive"],
        "agent": {
            "risk": "passive",
            "effects": ["osint_lookup"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["location_coordinates", "admin_boundaries"],
        },
    }

    location = OptString("", "Free-text location to geocode", required=True)
    use_cache = OptBool(True, "Use local geocode cache when available", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value: int, *, min_value: int = 1, max_value: int | None = None) -> int:
        try:
            parsed = int(str(value).strip())
        except Exception:
            parsed = default_value
        parsed = max(min_value, parsed)
        if max_value is not None:
            parsed = min(max_value, parsed)
        return parsed

    def run(self):
        query = str(self.location).strip()
        if not query:
            print_warning("Location value is empty; skipping geocode")
            return {
                "query": "",
                "skipped": True,
                "reason": "empty_query",
                "count": 0,
                "location": None,
            }

        timeout_seconds = float(self._to_int(self.timeout, 10, min_value=3, max_value=30))
        print_info(f"Geocoding location: {query}")

        resolution = normalize_location_sync(
            query,
            use_cache=bool(self.use_cache),
            timeout_seconds=timeout_seconds,
        )

        if resolution.rate_limited:
            retry = resolution.retry_after_seconds or 60
            print_warning(
                f"Geocoding rate-limited for '{query}'. Retry in about {retry}s. "
                "No upstream request was completed."
            )
            return {
                "query": query,
                "skipped": True,
                "reason": "rate_limited",
                "retry_after_seconds": retry,
                "count": 0,
                "location": None,
                "messages": [
                    f"Geocoding rate-limited for '{query}'. Retry in about {retry}s.",
                    "No upstream request was completed.",
                ],
            }

        if resolution.error and resolution.lat is None:
            print_warning(f"Unable to geocode '{query}': {resolution.error}")
            return {
                "query": query,
                "skipped": True,
                "reason": resolution.error,
                "count": 0,
                "location": None,
                "messages": [f"No geocode result found for '{query}'."],
            }

        normalized_value = (resolution.display_name or query).strip() or query
        location_payload = {
            "value": normalized_value,
            "input_query": query,
            "normalized": normalized_value.lower() != query.lower(),
            "lat": resolution.lat,
            "lon": resolution.lon,
            "location_label": normalized_value,
            "geo_confidence": round(resolution.confidence, 4),
            "country": resolution.country,
            "region": resolution.region,
            "state": resolution.region,
            "city": resolution.city,
            "postcode": resolution.postcode,
            "cache_hit": resolution.cache_hit,
            "properties": resolution.properties,
        }

        messages = [
            f"Geocoded '{query}' to '{normalized_value}' ({resolution.lat:.5f}, {resolution.lon:.5f}).",
            f"Confidence: {(resolution.confidence or 0.0):.2f}.",
            "Used cache." if resolution.cache_hit else "Used upstream geocoder.",
        ]
        for message in messages:
            print_success(message) if "Geocoded" in message else print_info(message)

        data = {
            "query": query,
            "skipped": False,
            "reason": "",
            "count": 1,
            "location": location_payload,
            "messages": messages,
        }

        if self.output_file:
            try:
                parent = os.path.dirname(str(self.output_file))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("skipped"):
            return [], []

        query = data.get("query", "location")
        loc = data.get("location") or {}
        if not loc:
            return [], []

        normalized = loc.get("value") or query
        nodes = []
        edges = []

        coord_label = f"{normalized} ({loc.get('lat')}, {loc.get('lon')})"
        nid = "geocoded_location"
        nodes.append({
            "id": nid,
            "label": coord_label,
            "group": "location",
            "icon": "📍",
        })
        edge_label = "normalized to" if loc.get("normalized") else "geocoded to"
        edges.append({
            "from": query,
            "to": nid,
            "label": edge_label,
        })

        admin_parts = [loc.get("city"), loc.get("region"), loc.get("country")]
        admin_label = ", ".join(part for part in admin_parts if part)
        if admin_label and admin_label.lower() != str(normalized).lower():
            aid = "geocoded_admin"
            nodes.append({
                "id": aid,
                "label": admin_label,
                "group": "location",
                "icon": "🗺️",
            })
            edges.append({
                "from": nid,
                "to": aid,
                "label": "admin area",
            })

        return nodes, edges
