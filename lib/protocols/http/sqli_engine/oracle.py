#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTP parameter oracle for SQLi probing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol


@dataclass
class ProbeResponse:
    status_code: int = 0
    text: str = ""
    elapsed: float = 0.0

    @property
    def length(self) -> int:
        return len(self.text or "")


SendFn = Callable[[str, Optional[float]], ProbeResponse]


class SqliOracle(Protocol):
    """Protocol for technique modules — any transport can implement this."""

    def baseline(self) -> ProbeResponse: ...
    def send(self, payload: str, *, timeout: Optional[float] = None) -> ProbeResponse: ...
    @property
    def original_value(self) -> str: ...
    @property
    def request_count(self) -> int: ...


@dataclass
class HttpParameterOracle:
    """
    Wraps a send callback for one (method, path, param) injection point.

    ``send_payload(payload, timeout=None)`` must perform the HTTP request and
    return ``(response_or_none, elapsed_seconds)``.
    """

    original_value: str
    send_payload: Callable[..., Any]
    _baseline: Optional[ProbeResponse] = field(default=None, init=False, repr=False)
    _requests: int = field(default=0, init=False, repr=False)

    @property
    def request_count(self) -> int:
        return self._requests

    def _normalize(self, response: Any, elapsed: float) -> ProbeResponse:
        if response is None:
            return ProbeResponse(status_code=0, text="", elapsed=elapsed)
        text = getattr(response, "text", None)
        if text is None and getattr(response, "content", None) is not None:
            raw = response.content
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
        return ProbeResponse(
            status_code=int(getattr(response, "status_code", 0) or 0),
            text=str(text or ""),
            elapsed=float(elapsed or 0.0),
        )

    def send(self, payload: str, *, timeout: Optional[float] = None) -> ProbeResponse:
        self._requests += 1
        if timeout is not None:
            result = self.send_payload(payload, timeout)
        else:
            result = self.send_payload(payload)
        if isinstance(result, ProbeResponse):
            return result
        if isinstance(result, tuple) and len(result) >= 2:
            return self._normalize(result[0], result[1])
        return self._normalize(result, 0.0)

    def baseline(self) -> ProbeResponse:
        if self._baseline is None:
            self._baseline = self.send(self.original_value or "1")
        return self._baseline
