#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time

from kittysploit import *

from lib.post.linux.session import LinuxSessionMixin
from lib.post.linux.sudo_policy_lists import ALWAYS_BLOCK, ALLOW_NOEXEC


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Gather Sudo Policy Audit (GTFO)",
        "description": "GTFO-style sudo policy audit (NOPASSWD / NOEXEC)",
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "references": [
            "https://gtfobins.github.io/",
            "https://attack.mitre.org/techniques/T1548.003/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.8,
            "noise": 0.35,
            "value": 0.95,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    block_file = OptString("", "Extra ALWAYS_BLOCK paths (local file)", False)
    noexec_file = OptString("", "Extra ALLOW_NOEXEC paths (local file)", False)
    audit_user = OptString("", "Limit audit to one user", False)
    test_noexec_bypass = OptBool(True, "Test NOPASSWD NOEXEC bypass", False)
    require_root = OptBool(True, "Require root for full audit", False)
    cleanup = OptBool(True, "Remove uploaded script after run", False)

    def _load_local_list(self, path: str) -> list[str]:
        entries: list[str] = []
        if not str(path or "").strip():
            return entries
        local = os.path.abspath(str(path).strip())
        if not os.path.isfile(local):
            raise ProcedureError(FailureType.ConfigurationError, f"List file not found: {local}")
        with open(local, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
        return entries

    @staticmethod
    def _bash_array(items: list[str]) -> str:
        quoted = " ".join(LinuxSessionMixin.linux_shell_quote(p) for p in items)
        return f"({quoted})"

    def _audit_script(self, *, block: list[str], noexec: list[str], user_filter: str, test_bypass: bool) -> str:
        block_arr = self._bash_array(block)
        noexec_arr = self._bash_array(noexec)
        user_filter_q = self.linux_shell_quote(user_filter) if user_filter else ""
        test_bypass_flag = "1" if test_bypass else "0"
        return f"""#!/bin/bash
set -u
TEST_BYPASS={test_bypass_flag}
USER_FILTER={user_filter_q!r}

ALWAYS_BLOCK={block_arr}
ALLOW_NOEXEC={noexec_arr}

viol=0

run_as_user() {{
  local user="$1"; shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  else
    su -s /bin/sh "$user" -c "$(printf '%q ' "$@")"
  fi
}}

check_base_state() {{
  local user="$1" bin="$2"
  [[ ! -e "$bin" ]] && {{ echo NOT_INSTALLED; return; }}
  if sudo -n -l -U "$user" "$bin" >/dev/null 2>&1; then
    if run_as_user "$user" sudo -n "$bin" -c true >/dev/null 2>&1; then
      echo NOPASSWD
    else
      echo PASSWD
    fi
  else
    echo BLOCKED
  fi
}}

check_noexec_flag() {{
  if sudo -n -l -U "$1" "$2" 2>/dev/null | grep -q NOEXEC; then
    echo SET
  else
    echo UNSET
  fi
}}

check_noexec_enforced() {{
  local u="$1" b="$2" o=""
  case "$b" in
    */vim|*/vi|*/view)   o=$(run_as_user "$u" sudo -n "$b" -c ':!id -u' 2>/dev/null);;
    */less)              o=$(echo '!id -u' | run_as_user "$u" sudo -n "$b" 2>/dev/null);;
    */python*|*/python3) o=$(run_as_user "$u" sudo -n "$b" -c 'import os;print(os.geteuid())' 2>/dev/null);;
    */perl)              o=$(run_as_user "$u" sudo -n "$b" -e 'print $<\\n' 2>/dev/null);;
    */awk)               o=$(run_as_user "$u" sudo -n "$b" 'BEGIN{{print PROCINFO["uid"]}}' 2>/dev/null);;
    *) echo UNKNOWN; return;;
  esac
  [[ "$o" == "0" ]] && echo BYPASSED || echo ENFORCED
}}

ADMIN_USERS=()
if [[ -n "$USER_FILTER" ]]; then
  ADMIN_USERS=("$USER_FILTER")
else
  for g in sudo wheel admin; do
    if getent group "$g" >/dev/null 2>&1; then
      IFS=, read -r -a members <<<"$(getent group "$g" | cut -d: -f4)"
      for m in "${{members[@]}}"; do
        [[ -n "$m" ]] && ADMIN_USERS+=("$m")
      done
    fi
  done
fi

if [[ ${{#ADMIN_USERS[@]}} -eq 0 ]]; then
  mapfile -t ADMIN_USERS < <(awk -F: '$3>=1000{{print $1}}' /etc/passwd)
fi

echo "KS_SUDO_AUDIT_BEGIN"
for user in "${{ADMIN_USERS[@]}}"; do
  [[ -z "$user" ]] && continue
  echo "KS_USER $user"
  for cmd in "${{ALWAYS_BLOCK[@]}}"; do
    st=$(check_base_state "$user" "$cmd")
    ok=NO
    [[ "$st" == BLOCKED || "$st" == NOT_INSTALLED ]] && ok=YES
    [[ "$ok" == NO ]] && viol=1
    echo "KS_ROW|$user|$cmd|$st|BLOCKED|$ok"
  done
  for cmd in "${{ALLOW_NOEXEC[@]}}"; do
    base=$(check_base_state "$user" "$cmd")
    case "$base" in
      BLOCKED|NOT_INSTALLED) st=$base ;;
      NOPASSWD|PASSWD)
        if [[ "$(check_noexec_flag "$user" "$cmd")" == UNSET ]]; then
          st=NOEXEC_MISSING
        elif [[ "$base" == NOPASSWD && "$TEST_BYPASS" == 1 ]]; then
          st=$(check_noexec_enforced "$user" "$cmd")
        else
          st=NOEXEC_SET
        fi
        ;;
      *) st=$base ;;
    esac
    ok=NO
    [[ "$st" == ENFORCED || "$st" == NOEXEC_SET || "$st" == BLOCKED || "$st" == NOT_INSTALLED ]] && ok=YES
    [[ "$ok" == NO ]] && viol=1
    echo "KS_ROW|$user|$cmd|$st|NOEXEC|$ok"
  done
done
echo "KS_SUMMARY violations=$viol"
exit "$viol"
"""

    def _parse_output(self, output: str) -> tuple[list[dict], int]:
        rows: list[dict] = []
        violations = 0
        current_user = ""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("KS_USER "):
                current_user = line.split(" ", 1)[1].strip()
            elif line.startswith("KS_ROW|"):
                parts = line.split("|")
                if len(parts) >= 6:
                    rows.append({
                        "user": parts[1],
                        "command": parts[2],
                        "state": parts[3],
                        "expect": parts[4],
                        "compliant": parts[5],
                    })
            elif line.startswith("KS_SUMMARY violations="):
                try:
                    violations = int(line.split("=", 1)[1].strip())
                except ValueError:
                    violations = 0
        return rows, violations

    def run(self):
        if not self.linux_require_linux():
            return False

        if self.require_root and not self.linux_is_root():
            print_error("Root privileges are required to audit sudo policy for all admin users.")
            print_info("Run as root or set require_root=false to attempt a limited audit.")
            return False

        try:
            block = list(ALWAYS_BLOCK) + self._load_local_list(str(self.block_file or ""))
            noexec = list(ALLOW_NOEXEC) + self._load_local_list(str(self.noexec_file or ""))
        except ProcedureError:
            raise
        except OSError as exc:
            raise ProcedureError(FailureType.ConfigurationError, f"Cannot read list file: {exc}") from exc

        user_filter = str(self.audit_user or "").strip()
        script_body = self._audit_script(
            block=block,
            noexec=noexec,
            user_filter=user_filter,
            test_bypass=bool(self.test_noexec_bypass),
        )

        remote_dir = "/tmp"
        remote_path = f"{remote_dir}/ks_sudo_policy_audit_{int(time.time())}.sh"
        print_info("=" * 60)
        print_status("Sudo policy audit")
        print_info(f"  ALWAYS_BLOCK entries: {len(block)}")
        print_info(f"  ALLOW_NOEXEC entries: {len(noexec)}")
        if user_filter:
            print_info(f"  Target user: {user_filter}")

        if not self.linux_upload_bytes(script_body.encode("utf-8"), remote_path, executable=True):
            print_error("Failed to upload audit script")
            return False

        print_status("Running sudo policy audit (this may take several minutes)...")
        output = self.linux_execute(f"bash {self.linux_shell_quote(remote_path)}", timeout=0)

        if self.cleanup:
            self.linux_execute(f"rm -f {self.linux_shell_quote(remote_path)}")

        if not output:
            print_warning("Audit script returned no output")
            return False

        rows, violations = self._parse_output(output)
        if not rows and "KS_SUDO_AUDIT_BEGIN" not in output:
            print_error("Unexpected audit output")
            print_info(output[:3000])
            return False

        bad_rows = [r for r in rows if r.get("compliant") == "NO"]
        users = sorted({r["user"] for r in rows})

        for user in users:
            user_bad = [r for r in bad_rows if r["user"] == user]
            if not user_bad:
                continue
            print_info("-" * 60)
            print_warning(f"Violations for user: {user} ({len(user_bad)})")
            for row in user_bad[:40]:
                print_warning(
                    f"  {row['command']} — state={row['state']} "
                    f"(expected {row['expect']})"
                )
            remaining = len(user_bad) - 40
            if remaining > 0:
                print_info(f"  ... {remaining} more violation(s)")

        print_info("=" * 60)
        if violations > 0 or bad_rows:
            print_error(f"POLICY VIOLATIONS DETECTED ({len(bad_rows)} non-compliant rule(s))")
            return False

        print_success("POLICY OK — no sudo GTFO policy violations detected")
        return True
