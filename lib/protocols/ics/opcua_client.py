#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OPC UA client helpers — anonymous endpoint probe, session wrapper, and node browse."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

try:
    from asyncua import Client  # type: ignore

    ASYNCUA_AVAILABLE = True
except ImportError:
    Client = None  # type: ignore
    ASYNCUA_AVAILABLE = False


@dataclass
class OpcUaProbeResult:
    host: str
    port: int
    url: str
    connected: bool = False
    anonymous: bool = False
    nodes: List[str] = field(default_factory=list)
    error: str = ""


class OpcUaClient:
    """Small synchronous wrapper around asyncua for listener and shell use."""

    def __init__(
        self,
        host: str,
        port: int = 4840,
        timeout: float = 5,
        *,
        ssl: bool = False,
        username: str = "",
        password: str = "",
        endpoint: str = "",
    ):
        self.host = str(host).strip()
        self.port = int(port)
        self.timeout = float(timeout or 5)
        self.ssl = bool(ssl)
        self.username = str(username or "")
        self.password = str(password or "")
        self.endpoint = str(endpoint or "").strip()
        self.url = self.endpoint or _build_url(self.host, self.port, self.ssl)
        self.connected = False
        self.last_error = ""
        self.anonymous = not self.username

    def connect(self, max_nodes: int = 10) -> OpcUaProbeResult:
        result = browse_opcua_nodes(
            self.host,
            self.port,
            self.ssl,
            max_nodes,
            username=self.username,
            password=self.password,
            endpoint=self.endpoint,
        )
        self.connected = bool(result.connected)
        self.last_error = result.error
        self.anonymous = bool(result.anonymous)
        return result

    def browse(self, node_id: str = "root", max_nodes: int = 50) -> OpcUaProbeResult:
        return browse_opcua_nodes(
            self.host,
            self.port,
            self.ssl,
            max_nodes,
            username=self.username,
            password=self.password,
            endpoint=self.endpoint,
            node_id=node_id,
        )


def opcua_available() -> bool:
    return ASYNCUA_AVAILABLE


def _build_url(host: str, port: int, ssl: bool = False) -> str:
    scheme = "opc.tcp" if not ssl else "opc.tcp"
    return f"{scheme}://{host}:{int(port)}"


async def _probe_async(
    url: str,
    max_nodes: int = 20,
    *,
    username: str = "",
    password: str = "",
    node_id: str = "root",
) -> OpcUaProbeResult:
    host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
    port = int(url.rsplit(":", 1)[-1].split("/")[0])
    result = OpcUaProbeResult(host=host, port=port, url=url)
    if not ASYNCUA_AVAILABLE:
        result.error = "asyncua not installed — pip install asyncua"
        return result
    client = Client(url=url, timeout=4)
    if username:
        client.set_user(username)
        client.set_password(password)
    try:
        await client.connect()
        result.connected = True
        result.anonymous = not bool(username)
        if node_id and node_id.lower() not in ("root", "objects"):
            root = client.get_node(node_id)
        elif str(node_id).lower() == "objects":
            root = client.nodes.objects
        else:
            root = client.get_root_node()
        children = await root.get_children()
        for child in children[: max(1, max_nodes)]:
            try:
                browse_name = await child.read_browse_name()
                result.nodes.append(f"{child.nodeid} {browse_name}")
            except Exception:
                result.nodes.append(str(child))
        return result
    except Exception as exc:
        result.error = str(exc)
        return result
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def probe_opcua_anonymous(
    host: str,
    port: int = 4840,
    ssl: bool = False,
    max_nodes: int = 20,
) -> OpcUaProbeResult:
    import asyncio

    url = _build_url(host, port, ssl)
    return asyncio.run(_probe_async(url, max_nodes))


def browse_opcua_nodes(
    host: str,
    port: int = 4840,
    ssl: bool = False,
    max_nodes: int = 50,
    *,
    username: str = "",
    password: str = "",
    endpoint: str = "",
    node_id: str = "root",
) -> OpcUaProbeResult:
    import asyncio

    url = endpoint or _build_url(host, port, ssl)
    return asyncio.run(
        _probe_async(
            url,
            max_nodes,
            username=username,
            password=password,
            node_id=node_id,
        )
    )
