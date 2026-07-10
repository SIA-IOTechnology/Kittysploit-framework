#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from email import policy
from email.header import decode_header
from email.parser import BytesParser
from typing import Any, Dict, List, Optional

from kittysploit import *

try:
	import imaplib
	IMAP_AVAILABLE = True
except ImportError:
	imaplib = None
	IMAP_AVAILABLE = False


def _decode_mime_header(value: str) -> str:
	if not value:
		return ""
	try:
		parts = decode_header(value)
		out = []
		for part, enc in parts:
			if isinstance(part, bytes):
				out.append(part.decode(enc or "utf-8", errors="replace"))
			else:
				out.append(str(part))
		return "".join(out)
	except Exception:
		return str(value)


def _email_body(msg) -> str:
	body = ""
	if msg.is_multipart():
		for part in msg.walk():
			if part.get_content_type() == "text/plain":
				payload = part.get_payload(decode=True)
				if payload:
					body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
				break
	else:
		payload = msg.get_payload(decode=True)
		if payload:
			body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
	return (body or "").strip()


class Module(Post):
	__info__ = {
		"name": "Email Inbox Search",
		"description": "Search the operator mailbox attached to an email reverse session via IMAP",
		"author": "KittySploit Team",
		"session_type": SessionType.EMAIL,
	'agent': {
	    'risk': '',
	    'effects': ['api_request'],
	    'expected_requests': 2,
	    'reversible': True,
	    'approval_required': False,
	    'produces': ['risk_signals'],
	    'cost': 1.5,
	    'noise': 0.5,
	    'value': 1.0,
	    'requires': 	    {'min_endpoints': 0,
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
	    'chain': 	    {'produces_capabilities': [],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	subject = OptString("", "Subject substring to match", False)
	from_addr = OptString("", "Sender substring to match", False)
	body_keyword = OptString("", "Body keyword to match", False)
	unread_only = OptBool(False, "Search only unread messages", False)
	max_results = OptInteger(25, "Maximum messages to display", False)
	mailbox = OptString("", "Mailbox to search (empty = session default)", False)
	show_body = OptBool(True, "Print message body preview", False)
	body_preview = OptInteger(400, "Body preview length in characters", False)

	def _session_id_value(self) -> str:
		session_id_attr = getattr(self, "session_id", "")
		if hasattr(session_id_attr, "value"):
			return str(session_id_attr.value or "").strip()
		return str(session_id_attr or "").strip()

	def _connection_data(self) -> Dict[str, Any]:
		session_id_value = self._session_id_value()
		if not session_id_value or not self.framework:
			return {}

		for listener in getattr(self.framework, "active_listeners", {}).values():
			if not hasattr(listener, "_session_connections"):
				continue
			conn = listener._session_connections.get(session_id_value)
			if isinstance(conn, dict):
				return conn

		session = self.framework.session_manager.get_session(session_id_value)
		if session and isinstance(session.data, dict):
			return session.data
		return {}

	def _imap_connect(self, data: Dict[str, Any]):
		if not IMAP_AVAILABLE:
			raise ProcedureError(
				FailureType.ConfigurationError, "imaplib is not available"
			)
		host = str(data.get("imap_host") or "")
		port = int(data.get("imap_port") or 993)
		user = str(data.get("imap_user") or "")
		password = str(data.get("imap_password") or "")
		use_ssl = bool(data.get("use_ssl_imap", True))
		if not host or not user or not password:
			raise ProcedureError(
				FailureType.ConfigurationError,
				"IMAP credentials not found in email session",
			)
		if use_ssl:
			conn = imaplib.IMAP4_SSL(host, port)
		else:
			conn = imaplib.IMAP4(host, port)
		conn.login(user, password)
		return conn

	def _matches(self, msg, subject_filter: str, from_filter: str, body_filter: str) -> bool:
		subject = _decode_mime_header(msg.get("Subject", ""))
		from_hdr = msg.get("From", "")
		body = _email_body(msg)
		if subject_filter and subject_filter.lower() not in subject.lower():
			return False
		if from_filter and from_filter.lower() not in from_hdr.lower():
			return False
		if body_filter and body_filter.lower() not in body.lower():
			return False
		return True

	def run(self):
		try:
			data = self._connection_data()
			if not data:
				print_error("Email session connection data not found")
				return False

			mailbox = str(self.mailbox or data.get("mailbox") or "INBOX").strip()
			subject_filter = str(self.subject or "").strip()
			from_filter = str(self.from_addr or "").strip()
			body_filter = str(self.body_keyword or "").strip()
			limit = max(1, int(self.max_results or 25))
			preview_len = max(40, int(self.body_preview or 400))

			print_info("=" * 80)
			print_status(f"Searching mailbox: {mailbox}")
			if subject_filter:
				print_info(f"  subject contains: {subject_filter}")
			if from_filter:
				print_info(f"  from contains: {from_filter}")
			if body_filter:
				print_info(f"  body contains: {body_filter}")
			if self.unread_only:
				print_info("  unread only: yes")

			conn = self._imap_connect(data)
			try:
				conn.select(mailbox, readonly=True)
				criteria = "UNSEEN" if self.unread_only else "ALL"
				typ, msg_data = conn.search(None, criteria)
				if typ != "OK" or not msg_data or not msg_data[0]:
					print_warning("No messages matched the search criteria")
					return True

				uids = msg_data[0].split()
				matches: List[Dict[str, Any]] = []
				for uid in reversed(uids):
					typ, fetched = conn.fetch(uid, "(RFC822)")
					if typ != "OK" or not fetched:
						continue
					raw = fetched[0][1]
					msg = BytesParser(policy=policy.default).parsebytes(raw)
					if not self._matches(msg, subject_filter, from_filter, body_filter):
						continue
					body = _email_body(msg)
					matches.append(
						{
							"uid": uid.decode() if isinstance(uid, bytes) else str(uid),
							"subject": _decode_mime_header(msg.get("Subject", "")),
							"from": msg.get("From", ""),
							"date": msg.get("Date", ""),
							"body": body,
						}
					)
					if len(matches) >= limit:
						break

				if not matches:
					print_warning("No messages matched the filters")
					return True

				print_info("-" * 80)
				print_success(f"Found {len(matches)} message(s)")
				for i, item in enumerate(matches, 1):
					print_info(f"\n[{i}] UID={item['uid']}")
					print_info(f"  From: {item['from']}")
					print_info(f"  Date: {item['date']}")
					print_info(f"  Subject: {item['subject']}")
					if self.show_body and item.get("body"):
						body = item["body"]
						if len(body) > preview_len:
							body = body[:preview_len] + "..."
						print_info(f"  Body: {body}")

				print_info("=" * 80)
				return True
			finally:
				try:
					conn.logout()
				except Exception:
					pass
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Email inbox search failed: {exc}"
			)
