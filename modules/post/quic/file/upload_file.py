#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from core.framework.failure import FailureType, ProcedureError
from lib.protocols.quic.quic_session_mixin import QuicSessionMixin


class Module(Post, QuicSessionMixin):
    """Upload a local file to a QUIC implant session."""

    __info__ = {
        "name": "QUIC Upload File",
        "description": "Upload a local file to the remote host via an active QUIC C2 session",
        "author": "KittySploit Team",
        "session_type": SessionType.QUIC,
    }

    local_file = OptFile("", "Local file path to upload", True)
    remote_path = OptString("", "Remote destination path/filename on the implant", True)

    def check(self):
        if not self._session_is_quic():
            print_error("This module requires an active QUIC session")
            return False
        if not os.path.isfile(str(self.local_file)):
            print_error(f"Local file not found: {self.local_file}")
            return False
        if not str(self.remote_path).strip():
            print_error("remote_path is required")
            return False
        try:
            self.open_quic()
            return True
        except ProcedureError as exc:
            print_error(str(exc))
            return False

    def run(self):
        local_path = str(self.local_file)
        remote = str(self.remote_path).strip()
        if not os.path.isfile(local_path):
            raise ProcedureError(FailureType.Unknown, f"Local file not found: {local_path}")

        print_status(f"Uploading {local_path} -> {remote}")
        client = self.open_quic()
        result = client.upload(local_path, remote)
        print_success(result)
        return True
