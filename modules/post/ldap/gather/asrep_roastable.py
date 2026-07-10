from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import UAC_NO_PREAUTH


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP AS-REP Roastable Users",
		"description": "List accounts with Kerberos pre-authentication disabled",
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "kerberos", "asrep", "preauth"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["ldap_access"],
				"produces_capabilities": ["asrep_targets"],
			},
		},
	}

	include_disabled = OptBool(False, "Include disabled accounts", False)
	admin_only = OptBool(False, "Only show adminCount=1 accounts", False)

	def run(self):
		try:
			print_info("=" * 80)
			print_status(f"AS-REP roastable users in {self.base_dn or '(domain)'}")
			filter_parts = [
				"(&(objectClass=user)",
				f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_NO_PREAUTH})",
			]
			if not self.include_disabled:
				filter_parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
			filter_parts.append(")")
			rows = self.search(
				"".join(filter_parts),
				["sAMAccountName", "userPrincipalName", "adminCount", "distinguishedName"],
			)
			if self.admin_only:
				rows = [row for row in rows if self.attr_int(row, "adminCount") == 1]

			if not rows:
				print_warning("No AS-REP roastable accounts found")
				return True

			for entry in rows:
				sam = self.attr_str(entry, "sAMAccountName")
				upn = self.attr_str(entry, "userPrincipalName")
				admin = self.attr_int(entry, "adminCount") == 1
				line = f"  {sam}"
				if upn:
					line += f" ({upn})"
				if admin:
					line += " [admin]"
				print_info(line)

			print_info("=" * 80)
			print_success(f"Found {len(rows)} AS-REP roastable account(s)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"AS-REP roastable enumeration failed: {exc}"
			)
