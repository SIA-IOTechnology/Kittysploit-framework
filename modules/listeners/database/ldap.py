#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LDAP listener - connects to an LDAP server and creates an interactive session.
"""

from kittysploit import *
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

class Module(Listener):
    """LDAP listener - creates interactive LDAP shell session"""

    __info__ = {
        'name': 'LDAP Listener',
        'description': 'LDAP directory listener - creates interactive LDAP shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.LDAP,
    }

    host = OptString("127.0.0.1", "LDAP server host", True)
    port = OptPort(389, "LDAP server port (389 or 636 for LDAPS)", True)
    username = OptString("", "Bind DN (leave empty for anonymous)", False)
    password = OptString("", "Bind password", False)
    use_ssl = OptBool(False, "Use LDAPS (TLS)", False)
    base_dn = OptString("", "Default search base DN", False)

    def run(self):
        """Connect to LDAP server and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 389
            username = str(self.username).strip() if self.username else ""
            password = str(self.password) if self.password else ""
            use_ssl = bool(self.use_ssl) if hasattr(self.use_ssl, '__bool__') else (str(self.use_ssl).lower() in ('true', '1', 'yes'))
            base_dn = str(self.base_dn).strip() if self.base_dn else ""

            print_status(f"Connecting to LDAP server {host}:{port}...")

            server = Server(
                host,
                port=port,
                use_ssl=use_ssl,
                get_info=ALL,
                connect_timeout=10
            )
            connection = Connection(
                server,
                user=username if username else None,
                password=password if password else None,
                auto_bind=True
            )

            if not connection.bound:
                print_error(f"LDAP bind failed: {connection.result}")
                return False

            print_success(f"Connected to LDAP server {host}:{port} (bound)")

            additional_data = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'use_ssl': use_ssl,
                'base_dn': base_dn,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except LDAPException as e:
            print_error(f"LDAP connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
