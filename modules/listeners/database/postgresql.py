#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PostgreSQL database listener - connects to a PostgreSQL server and creates an interactive session.
"""

from kittysploit import *
import psycopg2

class Module(Listener):
    """PostgreSQL database listener - creates interactive PostgreSQL shell session"""

    __info__ = {
        'name': 'PostgreSQL Listener',
        'description': 'PostgreSQL database listener - creates interactive PostgreSQL shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.POSTGRESQL,
    }

    host = OptString("127.0.0.1", "PostgreSQL server host", True)
    port = OptPort(5432, "PostgreSQL server port", True)
    username = OptString("postgres", "PostgreSQL username", True)
    password = OptString("", "PostgreSQL password", False)
    database = OptString("postgres", "Default database", False)

    def run(self):
        """Connect to PostgreSQL server and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 5432
            username = str(self.username) if self.username else "postgres"
            password = str(self.password) if self.password else ""
            database = str(self.database) if self.database else "postgres"

            print_status(f"Connecting to PostgreSQL server {host}:{port}...")

            connection = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                dbname=database,
                connect_timeout=10
            )
            connection.autocommit = False

            print_success(f"Connected to PostgreSQL server as {username}@{database}")

            additional_data = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'database': database,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except psycopg2.Error as e:
            print_error(f"PostgreSQL connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
