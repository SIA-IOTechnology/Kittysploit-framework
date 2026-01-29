#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MongoDB listener - connects to a MongoDB server and creates an interactive session.
"""

from kittysploit import *
from pymongo import MongoClient
from pymongo.errors import PyMongoError

class Module(Listener):
    """MongoDB listener - creates interactive MongoDB shell session"""

    __info__ = {
        'name': 'MongoDB Listener',
        'description': 'MongoDB NoSQL listener - creates interactive MongoDB shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.MONGODB,
    }

    host = OptString("127.0.0.1", "MongoDB server host", True)
    port = OptPort(27017, "MongoDB server port", True)
    username = OptString("", "MongoDB username (optional)", False)
    password = OptString("", "MongoDB password (optional)", False)
    database = OptString("admin", "Default database / auth source", False)

    def run(self):
        """Connect to MongoDB server and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 27017
            username = str(self.username).strip() if self.username else None
            password = str(self.password) if self.password else None
            database = str(self.database) if self.database else "admin"

            print_status(f"Connecting to MongoDB server {host}:{port}...")

            if username and password:
                uri = f"mongodb://{username}:{password}@{host}:{port}/{database}?authSource={database}"
            else:
                uri = f"mongodb://{host}:{port}/"
            connection = MongoClient(uri, serverSelectionTimeoutMS=10000)
            connection.admin.command('ping')

            print_success(f"Connected to MongoDB server at {host}:{port}")

            additional_data = {
                'host': host,
                'port': port,
                'username': username or '',
                'password': password or '',
                'database': database,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except PyMongoError as e:
            print_error(f"MongoDB connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
