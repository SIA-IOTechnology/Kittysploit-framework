#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from core.framework.failure import ProcedureError, FailureType
from lib.protocols.smb.smb_session_mixin import SMBSessionMixin


class Module(Post, SMBSessionMixin):
    """Upload a local file to a remote SMB share."""

    __info__ = {
        "name": "SMB Upload File",
        "description": "Uploads a local file to a remote SMB share via an active SMB session",
        "author": "KittySploit Team",
        "session_type": SessionType.SMB,
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    local_file = OptFile("", "Local file path to upload", True)
    share = OptString("C$", "Remote SMB share (e.g. C$, ADMIN$, public)", True)
    remote_path = OptString("\\Windows\\Temp", "Remote directory on the share", False)
    remote_filename = OptString("", "Remote filename (default: same as local filename)", False)
    overwrite = OptBool(True, "Overwrite file if it already exists", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_error("Framework or session manager not available")
            return False
        if not self.framework.session_manager.get_session(sid):
            print_error(f"Session {sid} not found")
            return False
        if not os.path.isfile(str(self.local_file)):
            print_error(f"Local file not found: {self.local_file}")
            return False
        try:
            self.open_smb()
            return True
        except Exception as e:
            print_error(f"SMB connection error: {e}")
            return False

    def _remote_file_path(self) -> tuple[str, str]:
        share = str(self.share or "C$").strip().strip("\\")
        remote_dir = str(self.remote_path or "\\").strip()
        if not remote_dir.startswith("\\"):
            remote_dir = "\\" + remote_dir
        remote_dir = remote_dir.rstrip("\\")
        local_path = os.path.abspath(str(self.local_file))
        filename = str(self.remote_filename or "").strip() or os.path.basename(local_path)
        remote_file = f"{remote_dir}\\{filename}" if remote_dir else f"\\{filename}"
        return share, remote_file

    def _remote_exists(self, client, share: str, remote_file: str) -> bool:
        parent = remote_file.rsplit("\\", 1)[0] or "\\"
        name = remote_file.rsplit("\\", 1)[-1]
        entries = client.list_path(share, parent if parent else "\\")
        return any(entry.get("name") == name for entry in entries)

    def _format_bytes(self, size: int) -> str:
        if size <= 0:
            return "0 B"
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024.0:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} PB"

    def run(self):
        try:
            info = self.get_smb_connection_info()
            share, remote_file = self._remote_file_path()
            local_path = os.path.abspath(str(self.local_file))
            local_size = os.path.getsize(local_path)

            print_info("=" * 70)
            print_info("SMB File Upload")
            print_info("=" * 70)
            print_info(f"Target: {info.get('host', 'unknown')}:{info.get('port', 445)}")
            print_info(f"Share: {share}")
            print_info(f"Local file: {local_path} ({self._format_bytes(local_size)})")
            print_info(f"Remote path: \\\\{info.get('host', '')}\\{share}{remote_file}")
            print_info("")

            client = self.open_smb()
            if self._remote_exists(client, share, remote_file) and not bool(self.overwrite):
                print_error(f"Remote file already exists: {share}:{remote_file}")
                print_info("Set overwrite=True to replace it")
                return False
            if self._remote_exists(client, share, remote_file):
                print_warning(f"Overwriting existing remote file: {share}:{remote_file}")

            print_status("Uploading file...")
            if not client.put_file(share, local_path, remote_file):
                raise ProcedureError(FailureType.Unknown, f"Upload failed for {share}:{remote_file}")

            print_success("Upload complete")
            print_info(f"Remote location: \\\\{info.get('host', '')}\\{share}{remote_file}")
            return True
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error uploading file: {e}")
