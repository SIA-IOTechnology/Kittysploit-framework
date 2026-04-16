#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize user targets and cheap port probing for scheme selection."""

import socket


class TargetResolver:
    """Prefer HTTPS for bare hostnames when 443 is reachable."""

    def normalize_target_input(self, raw_target: str) -> str:
        target = (raw_target or "").strip()
        if not target:
            return raw_target

        if target.startswith("http://") or target.startswith("https://"):
            return target

        if ":" in target:
            return target

        if self.is_port_open(target, 443, timeout=1.0):
            return f"https://{target}"

        return f"http://{target}"

    def is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False
