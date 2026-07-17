#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OPC UA bind listener — opens an OPC UA session for node browsing and diagnostics."""

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.opcua_client import OpcUaClient, opcua_available


class Module(Listener):
    __info__ = {
        "name": "OPC UA Client",
        "description": "Connects to an OPC UA server and creates an interactive OPC UA shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.OPCUA,
        "protocol": "opcua",
    }

    rhost = OptString("127.0.0.1", "Target OPC UA host", True)
    rport = OptPort(ICS_PROTOCOL_PORTS["opcua"], "OPC UA TCP port", True)
    endpoint = OptString("", "Full OPC UA endpoint URL (overrides host/port)", False)
    username = OptString("", "Optional OPC UA username", False)
    password = OptString("", "Optional OPC UA password", False)
    ssl = OptBool(False, "Use opc.tcp TLS/security endpoint hint", False)
    max_nodes = OptInteger(20, "Top-level nodes to browse on connect", False)

    def run(self):
        if not opcua_available():
            print_error("asyncua not installed — pip install asyncua")
            return False

        host = str(self.rhost).strip()
        port = int(self.rport)
        endpoint = str(self.endpoint or "").strip()
        username = str(self.username or "")
        password = str(self.password or "")

        target_label = endpoint or f"opc.tcp://{host}:{port}"
        auth_label = "anonymous" if not username else f"user={username}"
        print_status(f"Connecting to OPC UA {target_label} ({auth_label})...")

        client = OpcUaClient(
            host,
            port,
            float(self.timeout or 5),
            ssl=bool(self.ssl),
            username=username,
            password=password,
            endpoint=endpoint,
        )
        result = client.connect(int(self.max_nodes or 20))
        if not result.connected:
            print_error(result.error or f"OPC UA connection failed for {target_label}")
            return False

        print_success(f"OPC UA session established with {result.url}")
        print_info(f"  Authentication: {'anonymous' if result.anonymous else 'username/password'}")
        print_info(f"  Top-level nodes: {len(result.nodes)}")
        for node in result.nodes[: min(8, len(result.nodes))]:
            print_info(f"    {node}")

        additional_data = {
            "host": host,
            "port": port,
            "endpoint": result.url,
            "username": username,
            "password": password,
            "auth_mode": "anonymous" if result.anonymous else "username",
            "ssl": bool(self.ssl),
            "protocol": "opcua",
            "platform": "ics",
            "anonymous": result.anonymous,
            "nodes": result.nodes,
            "node_count": len(result.nodes),
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
