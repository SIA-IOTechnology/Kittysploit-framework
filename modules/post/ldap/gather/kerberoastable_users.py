from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import UAC_DONT_EXPIRE_PASSWD


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP Kerberoastable Users",
		"description": (
			"Native LDAP enum of users with servicePrincipalName (kerberoast targets). "
			"For live $krb5tgs$ hashes use post/ldap/gather/kerberoast."
		),
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
			"cost": 0.6,
			"noise": 0.25,
			"value": 1.3,
			"chain": {
				"consumes_capabilities": ["ldap_access"],
				"produces_capabilities": ["kerberoast_targets"],
				"suggested_followups": ["post/ldap/gather/kerberoast"],
			},
		},
	}

	include_disabled = OptBool(False, "Include disabled accounts", False)
	admin_only = OptBool(False, "Only show adminCount=1 accounts", False)

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

			print_info("=" * 80)
			print_success(f"Found {len(rows)} Kerberoastable account(s)")
			print_info("Next: use post/ldap/gather/kerberoast (request_hashes=true)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Kerberoastable user enumeration failed: {exc}"
			)
