#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WooCommerce Product Feeds plugin helpers."""

from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule

DEFAULT_SALT = "woo_product_feed_cron_salt"


class Woo_product_feeds(BaseModule):
    """Hard-coded cron salt nonce and admin-ajax trigger."""

    def woo_feeds_detected(self) -> bool:
        resp = self.http_request("GET", "/", timeout=12)
        if resp:
            body = (resp.text or "").lower()
            if "woo_product_feed" in body or "woocommerce-product-feeds" in body:
                return True
        resp2 = self.http_request(
            "GET",
            "/wp-content/plugins/woocommerce-product-feeds/",
            timeout=12,
        )
        return bool(resp2 and int(resp2.status_code or 0) not in (403, 404))

    @staticmethod
    def woo_feeds_nonces(salt: str) -> List[str]:
        raw = str(salt or DEFAULT_SALT)
        out = [hashlib.md5(raw.encode()).hexdigest()]
        out.append(hashlib.sha1(raw.encode()).hexdigest())
        out.append(hashlib.sha256(raw.encode()).hexdigest()[:32])
        return out

    def woo_feeds_trigger_cron(self, nonce: str) -> Tuple[int, str, bool]:
        action = f"woo_feed_cron_{nonce}"
        resp = self.http_request(
            "POST",
            "/wp-admin/admin-ajax.php",
            data={"action": action},
            timeout=25,
        )
        if not resp:
            return 0, "", False
        body = (resp.text or "")[:500]
        code = int(resp.status_code or 0)
        ok = code == 200 and body.strip() not in ("", "0", "-1")
        return code, body, ok