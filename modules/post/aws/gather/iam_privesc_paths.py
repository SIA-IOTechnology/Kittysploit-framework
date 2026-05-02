#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json
import fnmatch


class Module(Post):
    __info__ = {
        "name": "IAM PrivEsc Paths",
        "description": "Identify practical IAM privilege escalation paths for the current principal",
        "author": "KittySploit Team",
        "session_type": SessionType.AWS,
    }

    include_inline = OptBool(True, "Include inline user/role policies", False)
    include_managed = OptBool(True, "Include attached managed policies", False)
    max_roles = OptString("40", "Maximum IAM roles to inspect for trust relationships", False)
    export_json = OptString("", "Optional output JSON file for path findings", False)
    verbose = OptBool(False, "Show verbose action/resource details", False)

    PATH_RULES = [
        {
            "id": "passrole_lambda",
            "name": "PassRole + Lambda function write",
            "severity": "HIGH",
            "required_actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
            "any_actions": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
            "impact": "Can attach privileged role to Lambda and execute code under that role.",
            "validation": [
                "aws iam list-roles",
                "aws lambda list-functions",
                "aws lambda update-function-configuration --function-name <fn> --role <role-arn>",
                "aws lambda update-function-code --function-name <fn> --zip-file fileb://payload.zip",
            ],
        },
        {
            "id": "passrole_ec2",
            "name": "PassRole + EC2 instance launch",
            "severity": "HIGH",
            "required_actions": ["iam:PassRole", "ec2:RunInstances"],
            "any_actions": ["ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation"],
            "impact": "Can launch/modify EC2 with privileged instance profile and pivot credentials.",
            "validation": [
                "aws iam list-instance-profiles",
                "aws ec2 run-instances --image-id <ami> --iam-instance-profile Name=<profile> --instance-type t3.micro",
            ],
        },
        {
            "id": "attach_user_policy",
            "name": "Attach/Put policy on IAM user",
            "severity": "HIGH",
            "required_actions": [],
            "any_actions": ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey"],
            "impact": "Can grant stronger permissions to own/target users and mint long-lived credentials.",
            "validation": [
                "aws iam list-users",
                "aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "aws iam create-access-key --user-name <user>",
            ],
        },
        {
            "id": "attach_role_policy",
            "name": "Attach/Put policy on IAM role",
            "severity": "HIGH",
            "required_actions": [],
            "any_actions": ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
            "impact": "Can grant admin permissions to a role and/or relax trust policy for takeover.",
            "validation": [
                "aws iam list-roles",
                "aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "aws iam update-assume-role-policy --role-name <role> --policy-document file://trust.json",
            ],
        },
        {
            "id": "assumerole_wildcard",
            "name": "AssumeRole on wildcard resources",
            "severity": "MEDIUM",
            "required_actions": ["sts:AssumeRole"],
            "any_actions": [],
            "impact": "Can laterally move to assumable roles, potentially escalating privileges.",
            "validation": [
                "aws iam list-roles",
                "aws sts assume-role --role-arn <role-arn> --role-session-name ks-audit",
            ],
        },
        {
            "id": "secrets_decrypt",
            "name": "Secrets read + decrypt chain",
            "severity": "MEDIUM",
            "required_actions": [],
            "any_actions": ["secretsmanager:GetSecretValue", "ssm:GetParameter*", "kms:Decrypt"],
            "impact": "Can recover high-value credentials/secrets for horizontal or vertical pivot.",
            "validation": [
                "aws secretsmanager list-secrets",
                "aws secretsmanager get-secret-value --secret-id <id>",
                "aws ssm get-parameter --name <name> --with-decryption",
            ],
        },
    ]

    def run(self):
        try:
            print_info("Starting IAM privilege-escalation path analysis...")
            identity = self._aws_json("aws sts get-caller-identity 2>/dev/null")
            if not identity:
                print_error("Could not resolve caller identity")
                return False

            principal_arn = identity.get("Arn", "")
            print_info(f"Principal: {principal_arn}")
            print_info("=" * 80)

            policy_docs = self._collect_policies_for_current_principal(principal_arn)
            if not policy_docs:
                print_warning("No readable policy documents found for current principal")
                return True

            effective = self._build_effective_permissions(policy_docs)
            paths = self._identify_paths(effective, principal_arn)

            self._print_paths(paths, principal_arn, len(policy_docs))
            self._export_if_requested(paths, principal_arn)
            return True
        except Exception as e:
            print_error(f"Error during IAM PrivEsc path analysis: {e}")
            return False

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _aws_json(self, cmd):
        out = (self.cmd_execute(cmd) or "").strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except Exception:
            if self.verbose:
                print_warning(f"Non-JSON output for command: {cmd}")
                print_info(out)
            return None

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _normalize_action(self, action):
        return str(action).strip()

    def _action_matches(self, action, pattern):
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())

    def _collect_policies_for_current_principal(self, arn):
        docs = []
        if ":user/" in arn:
            username = arn.split(":user/", 1)[1]
            print_info(f"Detected IAM user principal: {username}")
            if self.include_managed:
                docs.extend(self._get_user_managed_policy_docs(username))
            if self.include_inline:
                docs.extend(self._get_user_inline_policy_docs(username))
            return docs

        if ":assumed-role/" in arn:
            role_part = arn.split(":assumed-role/", 1)[1]
            role_name = role_part.split("/", 1)[0]
            print_info(f"Detected assumed role principal: {role_name}")
            if self.include_managed:
                docs.extend(self._get_role_managed_policy_docs(role_name))
            if self.include_inline:
                docs.extend(self._get_role_inline_policy_docs(role_name))
            return docs

        if ":role/" in arn:
            role_name = arn.split(":role/", 1)[1]
            print_info(f"Detected IAM role principal: {role_name}")
            if self.include_managed:
                docs.extend(self._get_role_managed_policy_docs(role_name))
            if self.include_inline:
                docs.extend(self._get_role_inline_policy_docs(role_name))
            return docs

        print_warning("Unsupported principal type for automatic policy retrieval")
        return docs

    def _fetch_managed_policy_document(self, policy_arn):
        meta = self._aws_json(f"aws iam get-policy --policy-arn {policy_arn} 2>/dev/null")
        if not meta:
            return None
        version_id = (meta.get("Policy", {}) or {}).get("DefaultVersionId")
        if not version_id:
            return None
        version = self._aws_json(
            f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {version_id} 2>/dev/null"
        )
        if not version:
            return None
        return (version.get("PolicyVersion", {}) or {}).get("Document")

    def _get_user_managed_policy_docs(self, username):
        docs = []
        data = self._aws_json(
            f"aws iam list-attached-user-policies --user-name {username} 2>/dev/null"
        ) or {}
        for pol in data.get("AttachedPolicies", []):
            policy_arn = pol.get("PolicyArn", "")
            policy_name = pol.get("PolicyName", policy_arn)
            doc = self._fetch_managed_policy_document(policy_arn)
            if doc:
                docs.append({"source": f"user-attached:{policy_name}", "document": doc})
        return docs

    def _get_role_managed_policy_docs(self, role_name):
        docs = []
        data = self._aws_json(
            f"aws iam list-attached-role-policies --role-name {role_name} 2>/dev/null"
        ) or {}
        for pol in data.get("AttachedPolicies", []):
            policy_arn = pol.get("PolicyArn", "")
            policy_name = pol.get("PolicyName", policy_arn)
            doc = self._fetch_managed_policy_document(policy_arn)
            if doc:
                docs.append({"source": f"role-attached:{policy_name}", "document": doc})
        return docs

    def _get_user_inline_policy_docs(self, username):
        docs = []
        names = self._aws_json(f"aws iam list-user-policies --user-name {username} 2>/dev/null") or {}
        for name in names.get("PolicyNames", []):
            data = self._aws_json(
                f"aws iam get-user-policy --user-name {username} --policy-name {name} 2>/dev/null"
            ) or {}
            doc = data.get("PolicyDocument")
            if doc:
                docs.append({"source": f"user-inline:{name}", "document": doc})
        return docs

    def _get_role_inline_policy_docs(self, role_name):
        docs = []
        names = self._aws_json(f"aws iam list-role-policies --role-name {role_name} 2>/dev/null") or {}
        for name in names.get("PolicyNames", []):
            data = self._aws_json(
                f"aws iam get-role-policy --role-name {role_name} --policy-name {name} 2>/dev/null"
            ) or {}
            doc = data.get("PolicyDocument")
            if doc:
                docs.append({"source": f"role-inline:{name}", "document": doc})
        return docs

    def _build_effective_permissions(self, policy_docs):
        allowed_entries = []
        denied_entries = []

        for item in policy_docs:
            src = item.get("source", "unknown")
            doc = item.get("document", {})
            statements = self._as_list((doc or {}).get("Statement"))
            for stmt in statements:
                if "NotAction" in stmt:
                    continue
                actions = [self._normalize_action(a) for a in self._as_list(stmt.get("Action")) if str(a).strip()]
                resources = [str(r) for r in self._as_list(stmt.get("Resource"))] or ["*"]
                effect = str(stmt.get("Effect", "")).lower()
                entry = {"source": src, "actions": actions, "resources": resources}
                if effect == "allow":
                    allowed_entries.append(entry)
                elif effect == "deny":
                    denied_entries.append(entry)

        return {"allow": allowed_entries, "deny": denied_entries}

    def _is_action_allowed(self, effective, action_pattern):
        for entry in effective["allow"]:
            for action in entry["actions"]:
                if self._action_matches(action, action_pattern):
                    # best-effort deny handling
                    if self._is_action_explicitly_denied(effective, action):
                        continue
                    return True
        return False

    def _is_action_explicitly_denied(self, effective, concrete_action):
        for entry in effective["deny"]:
            for deny_action in entry["actions"]:
                if self._action_matches(concrete_action, deny_action) or self._action_matches(deny_action, concrete_action):
                    return True
        return False

    def _matching_actions(self, effective, action_pattern):
        matched = []
        for entry in effective["allow"]:
            for action in entry["actions"]:
                if self._action_matches(action, action_pattern):
                    if not self._is_action_explicitly_denied(effective, action):
                        matched.append(action)
        return sorted(set(matched))

    def _list_role_candidates(self):
        max_roles = self._to_int(self.max_roles, 40)
        data = self._aws_json("aws iam list-roles 2>/dev/null") or {}
        roles = data.get("Roles", [])
        return roles[:max_roles]

    def _identify_assumable_roles_hint(self):
        roles = self._list_role_candidates()
        if not roles:
            return []
        candidates = []
        for role in roles:
            arn = role.get("Arn", "")
            name = role.get("RoleName", "")
            trust = role.get("AssumeRolePolicyDocument", {}) or {}
            trust_str = json.dumps(trust).lower()
            if '"*"' in trust_str or ":root" in trust_str or "arn:aws:iam::" in trust_str:
                candidates.append({"role_name": name, "role_arn": arn})
        return candidates

    def _identify_paths(self, effective, principal_arn):
        paths = []

        for rule in self.PATH_RULES:
            missing_required = []
            matched_actions = []

            for req in rule["required_actions"]:
                req_matches = self._matching_actions(effective, req)
                if req_matches:
                    matched_actions.extend(req_matches)
                else:
                    missing_required.append(req)

            any_matches = []
            for any_act in rule["any_actions"]:
                any_matches.extend(self._matching_actions(effective, any_act))

            if missing_required:
                continue
            if rule["any_actions"] and not any_matches:
                continue

            matched_actions.extend(any_matches)
            path = {
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "principal": principal_arn,
                "matched_actions": sorted(set(matched_actions)),
                "impact": rule["impact"],
                "validation_commands": rule["validation"],
            }

            if rule["id"] == "assumerole_wildcard":
                hint_roles = self._identify_assumable_roles_hint()
                if hint_roles:
                    path["target_roles_hint"] = hint_roles[:15]

            paths.append(path)

        return paths

    def _print_paths(self, paths, principal_arn, policy_count):
        print_info(f"Analyzed principal: {principal_arn}")
        print_info(f"Policy documents analyzed: {policy_count}")
        print_info("=" * 80)

        if not paths:
            print_success("No concrete privilege-escalation path identified from analyzed permissions")
            return

        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_paths = sorted(paths, key=lambda p: severity_order.get(p["severity"], 99))

        print_warning(f"Identified {len(sorted_paths)} potential privilege-escalation path(s):")
        for idx, path in enumerate(sorted_paths, 1):
            print_warning(f"[{idx}] {path['name']} ({path['severity']})")
            print_info(f"  Impact: {path['impact']}")
            print_info(f"  Matched actions: {', '.join(path.get('matched_actions', []))}")

            if path.get("target_roles_hint"):
                print_info("  Role targets (hint):")
                for role in path["target_roles_hint"][:10]:
                    print_info(f"    - {role.get('role_name')} ({role.get('role_arn')})")

            print_info("  Validation commands:")
            for cmd in path.get("validation_commands", []):
                print_info(f"    - {cmd}")

            if self.verbose:
                print_info(f"  Path ID: {path.get('id')}")
            print_info("-" * 80)

    def _export_if_requested(self, paths, principal_arn):
        if not self.export_json:
            return
        payload = {
            "principal": principal_arn,
            "count": len(paths),
            "paths": paths,
        }
        try:
            with open(str(self.export_json), "w") as f:
                json.dump(payload, f, indent=2)
            print_success(f"Path findings exported to {self.export_json}")
        except Exception as e:
            print_error(f"Failed to export JSON: {e}")
