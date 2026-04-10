#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
from typing import Optional, Tuple

from core.framework.base_module import BaseModule
from core.framework.option.option_port import OptPort
from core.framework.option.option_string import OptString


class Ftp_server(BaseModule):
    """FTP server helper for exploit modules."""

    ftp_host = OptString("0.0.0.0", "FTP bind host", True)
    ftp_port = OptPort(2121, "FTP bind port", True)
    ftp_user = OptString("anonymous", "FTP username", True)
    ftp_password = OptString("anonymous", "FTP password", True)
    ftp_root = OptString(".", "FTP root directory", True)
    ftp_banner = OptString("FTP Server Ready - KittySploit", "FTP banner", False)

    def __init__(
        self,
        framework=None,
        host: str = "0.0.0.0",
        port: int = 2121,
        root_dir: str = ".",
        username: str = "anonymous",
        password: str = "anonymous",
        banner: str = "FTP Server Ready - KittySploit",
    ):
        super().__init__(framework)
        self.ftp_host = host
        self.ftp_port = int(port)
        self.ftp_user = username
        self.ftp_password = password
        self.ftp_root = root_dir
        self.ftp_banner = banner
        self.server = None
        self.thread = None

    @staticmethod
    def dependencies_available() -> bool:
        try:
            import pyftpdlib  # noqa: F401
            from pyftpdlib.authorizers import DummyAuthorizer  # noqa: F401
            from pyftpdlib.handlers import FTPHandler  # noqa: F401
            from pyftpdlib.servers import FTPServer  # noqa: F401
            return True
        except Exception:
            return False

    def start(self) -> Tuple[bool, Optional[str]]:
        try:
            from pyftpdlib.authorizers import DummyAuthorizer
            from pyftpdlib.handlers import FTPHandler
            from pyftpdlib.servers import FTPServer

            authorizer = DummyAuthorizer()
            authorizer.add_user(self.ftp_user, self.ftp_password, self.ftp_root, perm="elradfmw")

            class ExploitFTPHandler(FTPHandler):
                pass

            ExploitFTPHandler.authorizer = authorizer
            ExploitFTPHandler.banner = self.ftp_banner

            self.server = FTPServer((self.ftp_host, int(self.ftp_port)), ExploitFTPHandler)
            self.server.max_connections = 256
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            return True, None
        except Exception as e:
            return False, str(e)

    def stop(self):
        if self.server:
            try:
                self.server.close_all()
            except Exception:
                pass
