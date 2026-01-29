#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch listener - connects to an Elasticsearch cluster and creates an interactive session.
"""

from kittysploit import *
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError

class Module(Listener):
    """Elasticsearch listener - creates interactive Elasticsearch shell session"""

    __info__ = {
        'name': 'Elasticsearch Listener',
        'description': 'Elasticsearch listener - creates interactive Elasticsearch shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.ELASTICSEARCH,
    }

    host = OptString("127.0.0.1", "Elasticsearch host", True)
    port = OptPort(9200, "Elasticsearch HTTP port", True)
    username = OptString("", "Username (optional)", False)
    password = OptString("", "Password (optional)", False)
    use_ssl = OptBool(False, "Use HTTPS", False)

    def run(self):
        """Connect to Elasticsearch and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 9200
            username = str(self.username).strip() if self.username else None
            password = str(self.password) if self.password else None
            use_ssl = bool(self.use_ssl) if hasattr(self.use_ssl, '__bool__') else (str(self.use_ssl).lower() in ('true', '1', 'yes'))

            scheme = "https" if use_ssl else "http"
            url = f"{scheme}://{host}:{port}"

            print_status(f"Connecting to Elasticsearch at {url}...")

            if username and password:
                connection = Elasticsearch(
                    [url],
                    basic_auth=(username, password),
                    request_timeout=10,
                    verify_certs=False
                )
            else:
                connection = Elasticsearch(
                    [url],
                    request_timeout=10,
                    verify_certs=False
                )
            connection.ping()

            print_success(f"Connected to Elasticsearch at {host}:{port}")

            additional_data = {
                'host': host,
                'port': port,
                'username': username or '',
                'password': password or '',
                'use_ssl': use_ssl,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except ESConnectionError as e:
            print_error(f"Elasticsearch connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
