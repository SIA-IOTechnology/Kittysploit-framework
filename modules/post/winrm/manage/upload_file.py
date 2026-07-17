#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from kittysploit import *
from lib.protocols.winrm.winrm_session_mixin import WinRMSessionMixin


class Module(Post, WinRMSessionMixin):
	__info__ = {
		"name": "WinRM Upload File",
		"description": "Upload a local file to the remote host through an active WinRM session (pypsrp copy)",
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
				"produces_capabilities": ["file_write"],
				"suggested_followups": [
					"post/winrm/manage/powershell_exec",
					"post/winrm/manage/spawn_reverse_shell",
				],
			},
		},
	}

	local_file = OptFile("", "Local file path to upload", True)
	remote_path = OptString(
		"C:\\Windows\\Temp",
		"Remote directory or full remote file path",
		True,
	)
	remote_filename = OptString("", "Remote filename (default: same as local)", False)

	def _format_bytes(self, size: int) -> str:
		if size <= 0:
			return "0 B"
		value = float(size)
		for unit in ("B", "KB", "MB", "GB", "TB"):
			if value < 1024.0:
				return f"{value:.2f} {unit}"
			value /= 1024.0
		return f"{value:.2f} PB"

	def _resolve_remote_path(self, local_path: str) -> str:
		remote = str(self.remote_path or "").strip()
		if not remote:
			raise ProcedureError(FailureType.ConfigurationError, "remote_path is required")
		filename = str(self.remote_filename or "").strip() or os.path.basename(local_path)
		normalized = remote.replace("/", "\\").rstrip("\\")
		# Full remote file path if remote_filename unset and path has an extension
		if not str(self.remote_filename or "").strip() and os.path.splitext(normalized)[1]:
			return normalized
		return f"{normalized}\\{filename}"

	def check(self):
		sid = str(self.session_id or "").strip()
		if not sid:
			print_error("Session ID not set")
			return False
		if not os.path.isfile(str(self.local_file)):
			print_error(f"Local file not found: {self.local_file}")
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

			local_path = os.path.abspath(str(self.local_file))
			remote_file = self._resolve_remote_path(local_path)
			info = self.winrm_session_info()
			size = os.path.getsize(local_path)

			print_info("=" * 70)
			print_info("WinRM File Upload")
			print_info("=" * 70)
			print_info(f"Target: {info.get('host', 'unknown')}")
			print_info(f"Local:  {local_path} ({self._format_bytes(size)})")
			print_info(f"Remote: {remote_file}")
			print_info("")

			print_status("Uploading via WinRM...")
			self.winrm_copy(local_path, remote_file)
			print_success("Upload complete")
			print_info(f"Remote location: {remote_file}")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"WinRM upload error: {exc}")
