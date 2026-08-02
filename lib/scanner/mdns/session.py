#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""mDNS probe mixin — inherit ``MdnsProbeMixin`` in scanner/post modules."""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from lib.scanner.mdns.client import MdnsClient, MdnsEnumResult


class MdnsProbeMixin:
    """Expose ``self.enumerate_mdns()`` / ``self.open_mdns()`` on module classes."""

    def _mdns_opt(self, name: str, default=None):
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            attr = attr.value
        return attr if attr is not None else default

    def open_mdns(self, timeout: Optional[float] = None, port: Optional[int] = None) -> MdnsClient:
        to = float(timeout if timeout is not None else self._mdns_opt("timeout") or 2.0)
        p = int(port if port is not None else self._mdns_opt("port") or self._mdns_opt("rport") or 5353)
        return MdnsClient(timeout=to, port=p)

    def enumerate_mdns(
        self,
        host: str = "",
        *,
        queries: Sequence[str] | None = None,
        multicast: bool = False,
        resolve_srv: bool = True,
        timeout: Optional[float] = None,
    ) -> MdnsEnumResult:
        client = self.open_mdns(timeout=timeout)
        return client.enumerate(
            host=host,
            queries=queries,
            multicast=multicast,
            resolve_srv=resolve_srv,
        )

    def mdns_result_as_dict(self, result: MdnsEnumResult) -> Dict[str, Any]:
        return {
            "detected": result.detected,
            "mode": result.mode,
            "services": [
                {
                    "instance": s.instance,
                    "service_type": s.service_type,
                    "host": s.host,
                    "port": s.port,
                    "addresses": list(s.addresses),
                    "txt": dict(s.txt),
                }
                for s in result.services
            ],
            "names": list(result.names),
            "queries_hit": list(result.queries_hit),
            "suggested_modules": list(result.suggested_modules),
            "error": result.error,
        }
