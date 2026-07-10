#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OPC UA client helpers — anonymous endpoint probe and node browse."""

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


def opcua_available() -> bool:
    return ASYNCUA_AVAILABLE


def _build_url(host: str, port: int, ssl: bool = False) -> str:
    scheme = "opc.tcp" if not ssl else "opc.tcp"
    return f"{scheme}://{host}:{int(port)}"


async def _probe_async(url: str, max_nodes: int = 20) -> OpcUaProbeResult:
    host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
    port = int(url.rsplit(":", 1)[-1].split("/")[0])
    result = OpcUaProbeResult(host=host, port=port, url=url)
    if not ASYNCUA_AVAILABLE:
        result.error = "asyncua not installed — pip install asyncua"
        return result
    client = Client(url=url)
    try:
        await client.connect()
        result.connected = True
        result.anonymous = True
        root = client.get_root_node()
        children = await root.get_children()
        for child in children[: max(1, max_nodes)]:
            try:
                result.nodes.append(await child.read_browse_name())
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
) -> OpcUaProbeResult:
    return probe_opcua_anonymous(host, port, ssl, max_nodes)
