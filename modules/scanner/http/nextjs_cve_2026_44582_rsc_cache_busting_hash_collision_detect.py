#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import secrets
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import ensure_nextjs_target


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js _rsc weak hash collision (CVE-2026-44582) — detect",
        "description": (
            "Pure-Python legacy cache-busting hash + birthday search; positive if a colliding tuple "
            "is found within max_attempts. Does not import other Kittysploit modules."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "cve": "CVE-2026-44582",
        "references": ["https://github.com/advisories/GHSA-vfv6-92ff-j949"],
        "tags": ["scanner", "nextjs", "rsc", "cache", "hash"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
    },
    }

    victim_prefetch = OptString("1", "Victim prefetch", required=False, advanced=True)
    victim_segment_prefetch = OptString("/_tree", "Victim segment prefetch", required=False, advanced=True)
    victim_state_tree = OptString(
        '%5B%22%22%2C%7B%22a%22%3A%22victim%22%7D%5D',
        "Victim state tree (encoded)",
        required=False,
        advanced=True,
    )
    victim_next_url = OptString("/dashboard", "Victim next-url", required=False, advanced=True)
    max_attempts = OptInteger(500_000, "Birthday search cap (lower default for scans)", required=False)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    @staticmethod
    def legacy_hash(prefetch: str, segment_prefetch: str, state_tree: str, next_url: str) -> str:
        s = f"{prefetch}|{segment_prefetch}|{state_tree}|{next_url}"
        h = 0x811C9DC5
        for ch in s:
            h ^= ord(ch)
            h = (h * 0x01000193) & 0xFFFFFFFF
        return Module._to_base36(h)

    @staticmethod
    def _to_base36(n: int) -> str:
        n &= 0xFFFFFFFF
        if n == 0:
            return "0"
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        out = []
        while n:
            n, r = divmod(n, 36)
            out.append(digits[r])
        return "".join(reversed(out))

    def _victim_tuple(self):
        return {
            "prefetch": str(self._o(self.victim_prefetch) or "1").strip() or "1",
            "segment_prefetch": str(self._o(self.victim_segment_prefetch) or "/_tree").strip() or "/_tree",
            "state_tree": str(self._o(self.victim_state_tree) or "").strip()
            or '%5B%22%22%2C%7B%22a%22%3A%22victim%22%7D%5D',
            "next_url": str(self._o(self.victim_next_url) or "/dashboard").strip() or "/dashboard",
        }

    def find_collision(self, target_hash: str, max_attempts: int):
        fixed_pf = "1"
        fixed_sp = "/_tree"
        attempts = 0
        while attempts < max_attempts:
            n = secrets.randbits(48)
            state_tree = f'%5B%22%22%2C%7B%22a%22%3A%22{n:x}%22%7D%5D'
            next_url = f"/p{n & 0xFFFF:04x}"
            h = self.legacy_hash(fixed_pf, fixed_sp, state_tree, next_url)
            attempts += 1
            if h == target_hash:
                return {"attempts": attempts, "hash": h, "state_tree": state_tree, "next_url": next_url}
        return None

    def run(self):
        if not ensure_nextjs_target(self):
            return False
        vt = self._victim_tuple()
        th = self.legacy_hash(vt["prefetch"], vt["segment_prefetch"], vt["state_tree"], vt["next_url"])
        cap = max(1000, int(self._o(self.max_attempts)))
        t0 = time.perf_counter()
        res = self.find_collision(th, cap)
        dt = time.perf_counter() - t0
        if res:
            self.set_info(
                reason="collision found",
                attempts=res["attempts"],
                seconds=round(dt, 2),
                target_hash=th,
                confidence="high",
            )
            return True
        self.set_info(reason=f"no collision in {cap} tries", target_hash=th, seconds=round(dt, 2))
        return False
