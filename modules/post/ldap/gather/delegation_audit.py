from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import (
	UAC_TRUSTED_FOR_DELEGATION,
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
)


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP Delegation Audit",
		"description": "Audit unconstrained, constrained, and resource-based constrained delegation",
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "delegation", "rbcd", "unconstrained", "constrained"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 4,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["ldap_access", "kerberoast_targets"],
				"produces_capabilities": ["admin_access"],
				"suggested_followups": [
					"auxiliary/scanner/smb/session_acquire",
					"scanner/ldap/unconstrained_delegation",
				],
			},
		},
	}

	show_rbcd_principals = OptBool(True, "Resolve RBCD security descriptor principals", False)

	def _print_entries(self, title: str, rows, name_fn):
		print_info("-" * 80)
		print_status(title)
		if not rows:
			print_info("  (none)")
			return
		for entry in rows[:50]:
			print_info(f"  - {name_fn(entry)}")
		if len(rows) > 50:
			print_info(f"  ... and {len(rows) - 50} more")

	def _rbcd_principals(self, raw_values):
		principals = []
		for raw in raw_values or []:
			text = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
			for token in text.replace("(", " ").replace(")", " ").split():
				if token.startswith("S-1-"):
					principals.append(self.resolve_sid(token))
				elif token and token not in ("O:", "G:", "D:", "S:"):
					principals.append(token)
		return sorted(set(p for p in principals if p))

	def run(self):
		try:
			print_info("=" * 80)
			print_status(f"Delegation audit for {self.base_dn or '(domain)'}")

			unc_computers = self.search(
				"(&(objectClass=computer)"
				f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_FOR_DELEGATION})"
				"(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
				["sAMAccountName", "dNSHostName"],
			)
			unc_users = self.search(
				"(&(objectClass=user)(!(objectClass=computer))"
				f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_FOR_DELEGATION})"
				"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
				["sAMAccountName", "adminCount"],
			)
			self._print_entries(
				"Unconstrained delegation — computers",
				unc_computers,
				lambda e: self.attr_str(e, "dNSHostName") or self.attr_str(e, "sAMAccountName"),
			)
			self._print_entries(
				"Unconstrained delegation — users",
				unc_users,
				lambda e: self.attr_str(e, "sAMAccountName"),
			)

			constrained = self.search(
				"(&(objectClass=user)"
				f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_TO_AUTH_FOR_DELEGATION})"
				"(msDS-AllowedToDelegateTo=*))",
				["sAMAccountName", "msDS-AllowedToDelegateTo", "dNSHostName"],
			)
			print_info("-" * 80)
			print_status("Constrained delegation")
			if not constrained:
				print_info("  (none)")
			else:
				for entry in constrained[:50]:
					name = self.attr_str(entry, "sAMAccountName") or self.attr_str(entry, "dNSHostName")
					targets = self.attr_list(entry, "msDS-AllowedToDelegateTo")
					print_info(f"  - {name}")
					for target in targets[:8]:
						print_info(f"      -> {target}")

			rbcd_rows = self.search(
				"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
				["sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
			)
			print_info("-" * 80)
			print_status("Resource-based constrained delegation (RBCD)")
			if not rbcd_rows:
				print_info("  (none)")
			else:
				for entry in rbcd_rows[:50]:
					name = self.attr_str(entry, "sAMAccountName") or self.attr_str(entry, "dNSHostName")
					print_info(f"  - {name}")
					if self.show_rbcd_principals:
						principals = self._rbcd_principals(
							self.attr_list(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
						)
						for principal in principals[:10]:
							print_info(f"      allowed: {principal}")

			dom = self.get_domain_object()
			if dom and self.attr_list(dom, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
				print_warning("RBCD is configured on the domain object itself (critical)")

			print_info("=" * 80)
			print_success("Delegation audit completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Delegation audit failed: {exc}"
			)
