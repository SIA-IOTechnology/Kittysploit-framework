#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from kittysploit import *
import redis

class Module(Listener):

    __info__ = {
        'name': 'Redis Listener',
        'description': 'Redis in-memory store listener - creates interactive Redis shell session',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.REDIS,
    }

    host = OptString("127.0.0.1", "Redis server host", True)
    port = OptPort(6379, "Redis server port", True)
    password = OptString("", "Redis password (optional)", False)
    db = OptInteger(0, "Redis database index (0-15)", False)

    def run(self):
        """Connect to Redis server and create session"""
        try:
            host = str(self.host) if self.host else "127.0.0.1"
            port = int(self.port) if self.port else 6379
            password = str(self.password) if self.password else None
            db = int(self.db) if self.db is not None else 0

            print_status(f"Connecting to Redis server {host}:{port}...")

            connection = redis.Redis(
                host=host,
                port=port,
                password=password,
                db=db,
                socket_connect_timeout=10,
                decode_responses=True
            )
            connection.ping()

            print_success(f"Connected to Redis server at {host}:{port} (db{db})")

            additional_data = {
                'host': host,
                'port': port,
                'password': password or '',
                'db': db,
                'connection': connection,
            }

            return (connection, host, port, additional_data)

        except redis.RedisError as e:
            print_error(f"Redis connection failed: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
