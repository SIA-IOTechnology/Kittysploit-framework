from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient

import re


class Module(Post, RedisClient):

    __info__ = {
        "name": "Redis ACL Audit",
        "description": "Review Redis ACL users and highlight risky permissions, weak user posture, and dangerous command access",
        "author": "KittySploit Team",
        "session_type": SessionType.REDIS,
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
        'requires':         {'min_endpoints': 0,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
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

    show_raw = OptBool(False, "Print raw ACL LIST entries after masking password hashes", False)

    DANGEROUS_COMMANDS = (
        "config",
        "module",
        "slaveof",
        "replicaof",
        "migrate",
        "restore",
        "flushall",
        "flushdb",
        "eval",
        "evalsha",
        "function",
        "acl",
        "save",
        "bgsave",
        "shutdown",
    )

    def run(self):
        try:
            info = self.get_session_info()
            print_info("=" * 80)
            print_status("Redis ACL audit")
            print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")

            entries = self.acl_list()
            if not entries:
                print_warning("ACL LIST returned no entries")
                return True

            users = [self._parse_acl_entry(entry) for entry in entries]
            findings = 0

            print_info("-" * 80)
            print_status("Users")
            for user in users:
                risk = self._risk_user(user)
                findings += 1 if risk else 0
                prefix = print_warning if risk else print_success
                prefix(f"{user['name']}: {user['state']} ({', '.join(risk) if risk else 'least obvious risk not detected'})")
                print_info(f"  keys: {', '.join(user['keys']) if user['keys'] else '(none)'}")
                print_info(f"  channels: {', '.join(user['channels']) if user['channels'] else '(none)'}")
                dangerous = self._dangerous_access(user["commands"])
                if dangerous:
                    print_warning(f"  dangerous commands: {', '.join(dangerous)}")
                else:
                    print_info("  dangerous commands: not explicitly granted")

            if bool(self.show_raw):
                print_info("-" * 80)
                print_status("Raw ACL entries")
                for entry in entries:
                    print_info(f"  {self._mask_hashes(entry)}")

            print_info("=" * 80)
            if findings:
                print_warning(f"ACL audit completed with {findings} user(s) requiring review")
            else:
                print_success("ACL audit completed without obvious high-risk ACL users")
            return True
        except ProcedureError:
            raise
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"Redis ACL audit failed: {exc}")

    def _parse_acl_entry(self, entry: str) -> dict:
        raw = self._text(entry)
        tokens = raw.split()
        user = {
            "name": "(unknown)",
            "state": "unknown",
            "commands": [],
            "keys": [],
            "channels": [],
            "password_tokens": [],
            "raw": raw,
        }
        if len(tokens) >= 2 and tokens[0] == "user":
            user["name"] = tokens[1]
            tokens = tokens[2:]

        for token in tokens:
            if token in ("on", "off"):
                user["state"] = token
            elif token.startswith(("+", "-", "~", "&", ">", "#", "!")):
                if token.startswith((">", "#", "!")):
                    user["password_tokens"].append(token)
                elif token.startswith("~"):
                    user["keys"].append(token)
                elif token.startswith("&"):
                    user["channels"].append(token)
                else:
                    user["commands"].append(token)
        return user

    def _risk_user(self, user: dict) -> list:
        risks = []
        commands = [cmd.lower() for cmd in user["commands"]]
        if user["state"] == "off":
            return risks
        if user["name"] == "default":
            risks.append("default user enabled")
        if "nopass" in user["raw"].lower():
            risks.append("nopass")
        if "+@all" in commands or "+allcommands" in commands:
            risks.append("all commands")
        if "~*" in user["keys"]:
            risks.append("all keys")
        if self._dangerous_access(user["commands"]):
            risks.append("dangerous command access")
        return risks

    def _dangerous_access(self, commands: list) -> list:
        lowered = [cmd.lower().lstrip("+") for cmd in commands if cmd.startswith("+")]
        if "@all" in lowered or "allcommands" in lowered:
            return list(self.DANGEROUS_COMMANDS)
        hits = []
        for dangerous in self.DANGEROUS_COMMANDS:
            if dangerous in lowered or f"@{dangerous}" in lowered:
                hits.append(dangerous)
        return hits

    def _mask_hashes(self, entry: str) -> str:
        return re.sub(r"([>#!])\S+", r"\1***masked***", self._text(entry))

    def _text(self, value) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)
