#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gRPC server reflection and exposure detection helpers."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    GRPC_AVAILABLE = True
except ImportError:
    grpc = None  # type: ignore
    reflection_pb2 = None  # type: ignore
    reflection_pb2_grpc = None  # type: ignore
    GRPC_AVAILABLE = False


@dataclass
class GrpcProbeResult:
    host: str
    port: int
    detected: bool = False
    reflection_enabled: bool = False
    services: List[str] = field(default_factory=list)
    heuristic_only: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "detected": self.detected,
            "reflection_enabled": self.reflection_enabled,
            "services": self.services,
            "heuristic_only": self.heuristic_only,
            "error": self.error,
        }


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex((host, int(port))) == 0
    except Exception:
        return False
    finally:
        sock.close()


def _probe_reflection(host: str, port: int, timeout: float, use_ssl: bool) -> GrpcProbeResult:
    result = GrpcProbeResult(host=host, port=int(port))
    if not GRPC_AVAILABLE:
        result.error = "grpcio/grpcio-reflection not installed"
        return result

    target = f"{host}:{int(port)}"
    try:
        if use_ssl:
            channel = grpc.secure_channel(target, grpc.ssl_channel_credentials())
        else:
            channel = grpc.insecure_channel(
                target,
                options=(("grpc.max_receive_message_length", 4 * 1024 * 1024),),
            )
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        responses = stub.ServerReflectionInfo(iter([request]), timeout=timeout)
        services: List[str] = []
        for resp in responses:
            if resp.HasField("list_services_response"):
                for service in resp.list_services_response.service:
                    services.append(service.name)
        result.detected = True
        result.reflection_enabled = True
        result.services = sorted(set(services))
        channel.close()
    except Exception as exc:
        result.error = str(exc)
    return result


def probe_grpc(
    host: str,
    port: int = 50051,
    timeout: float = 5.0,
    use_ssl: bool = False,
    http_headers: Optional[Dict[str, str]] = None,
) -> GrpcProbeResult:
    result = GrpcProbeResult(host=host, port=int(port))
    if not _tcp_open(host, port, timeout):
        result.error = "TCP port closed"
        return result

    if GRPC_AVAILABLE:
        reflected = _probe_reflection(host, port, timeout, use_ssl)
        if reflected.reflection_enabled:
            return reflected
        if reflected.error and "UNIMPLEMENTED" not in reflected.error.upper():
            result.error = reflected.error

    headers = {str(k).lower(): str(v) for k, v in (http_headers or {}).items()}
    grpc_headers = [k for k in headers if "grpc" in k or k in ("server", "via", "x-powered-by")]
    if grpc_headers or headers.get("content-type", "").startswith("application/grpc"):
        result.detected = True
        result.heuristic_only = True
        if not result.error:
            result.error = "gRPC-like headers observed; install grpcio for reflection probe"
        return result

    result.detected = True
    result.heuristic_only = True
    result.error = result.error or "gRPC port open; reflection not confirmed"
    return result
