#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSSQL listener - connects to a Microsoft SQL Server and creates an interactive session.
"""

from kittysploit import *
import pymssql

class Module(Listener):
    """MSSQL listener - creates interactive MSSQL shell session"""

    __info__ = {
        'name': 'MSSQL Listener',
        'description': 'Microsoft SQL Server listener - creates interactive MSSQL shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.MSSQL,
    }

    host = OptString("127.0.0.1", "MSSQL server host", True)
    port = OptPort(1433, "MSSQL server port", True)
    username = OptString("sa", "MSSQL username", True)
    password = OptString("", "MSSQL password", False)
    database = OptString("master", "Default database", False)

    def run(self):
        """Connect to MSSQL server and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 1433
            username = str(self.username) if self.username else "sa"
            password = str(self.password) if self.password else ""
            database = str(self.database) if self.database else "master"

            print_status(f"Connecting to MSSQL server {host}:{port}...")

            connection = pymssql.connect(
                server=host,
                port=port,
                user=username,
                password=password,
                database=database,
                login_timeout=10
            )

            print_success(f"Connected to MSSQL server as {username}@{database}")

            additional_data = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'database': database,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except pymssql.Error as e:
            print_error(f"MSSQL connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
