#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Download File",
		"description": "Download a remote file through an active WinRM session (pypsrp fetch)",
		"author": "KittySploit Team",
		"platform": Platform.WINDOWS,
		"session_type": SessionType.WINRM,
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["authenticated_session"],
				"produces_capabilities": ["file_read"],
				"suggested_followups": [],
			},
		},
	}

	remote_path = OptString("", "Remote file path to download", True)
	local_path = OptString("", "Local destination path (file or directory)", True)

	def _format_bytes(self, size: int) -> str:
		if size <= 0:
			return "0 B"
		value = float(size)
		for unit in ("B", "KB", "MB", "GB", "TB"):
			if value < 1024.0:
				return f"{value:.2f} {unit}"
			value /= 1024.0
		return f"{value:.2f} PB"

	def _resolve_local_path(self, remote_path: str) -> str:
		dest = str(self.local_path or "").strip()
		if not dest:
			raise ProcedureError(FailureType.ConfigurationError, "local_path is required")
		if os.path.isdir(dest) or dest.endswith(("/", "\\")):
			filename = os.path.basename(remote_path.replace("\\", "/"))
			return os.path.join(os.path.abspath(dest.rstrip("/\\")), filename)
		return os.path.abspath(dest)

	def check(self):
		sid = str(self.session_id or "").strip()
		if not sid:
			print_error("Session ID not set")
			return False
		if not str(self.remote_path or "").strip():
			print_error("remote_path is required")
			return False
		try:
			self.get_winrm_connection()
			return True
		except Exception as exc:
			print_error(f"WinRM connection error: {exc}")
			return False

	def run(self):
		try:
			if not self.check():
				return False

			remote_file = str(self.remote_path).strip().replace("/", "\\")
			local_file = self._resolve_local_path(remote_file)
			info = self.winrm_session_info()

			parent = os.path.dirname(local_file)
			if parent and not os.path.isdir(parent):
				os.makedirs(parent, exist_ok=True)

			print_info("=" * 70)
			print_info("WinRM File Download")
			print_info("=" * 70)
			print_info(f"Target: {info.get('host', 'unknown')}")
			print_info(f"Remote: {remote_file}")
			print_info(f"Local:  {local_file}")
			print_info("")

			print_status("Downloading via WinRM...")
			self.winrm_fetch(remote_file, local_file)

			size = os.path.getsize(local_file) if os.path.isfile(local_file) else 0
			print_success("Download complete")
			print_info(f"Saved to: {local_file} ({self._format_bytes(size)})")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM download error: {exc}")
