#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for QUIC post modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.framework.failure import FailureType, ProcedureError
from lib.protocols.quic.session_client import QuicSessionClient

if TYPE_CHECKING:
    from kittysploit import Post


class QuicSessionMixin:
    """Resolve the active QUIC session client from the framework."""

    def open_quic(self: "Post") -> QuicSessionClient:
        session_id = str(getattr(self.session_id, "value", None) or self.session_id or "").strip()
        if not session_id:
            raise ProcedureError(FailureType.ConfigurationError, "Session ID not set")

        client = QuicSessionClient.from_session(self.framework, session_id)
        if not client:
            raise ProcedureError(
                FailureType.ConfigurationError,
                "QUIC client not available — use a session from listeners/multi/reverse_quic",
            )
        return client

    def _session_is_quic(self: "Post") -> bool:
        session_id = str(getattr(self.session_id, "value", None) or self.session_id or "").strip()
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return False
        session = self.framework.session_manager.get_session(session_id)
        if not session:
            return False
        st = getattr(session, "session_type", "") or ""
        if hasattr(st, "value"):
            st = st.value
        return str(st).lower() == "quic"
