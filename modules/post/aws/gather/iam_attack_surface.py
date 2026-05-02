#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json
import fnmatch


class Module(Post):
    __info__ = {
        "name": "IAM Attack Surface Mapping",
        "description": "Map dangerous IAM permissions on current principal to identify privilege escalation paths",
        "author": "KittySploit Team",
        "session_type": SessionType.AWS,
    }

    include_inline = OptBool(True, "Include inline user/role policies", False)
    include_managed = OptBool(True, "Include attached managed policies", False)
    verbose = OptBool(False, "Show detailed matching actions", False)

    DANGEROUS_PATTERNS = {
        "Privilege administration": [
            "iam:*",
            "iam:CreateUser",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:PassRole",
            "iam:UpdateAssumeRolePolicy",
        ],
        "Role pivoting": [
            "sts:AssumeRole",
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "ecs:RunTask",
            "ec2:RunInstances",
        ],
        "Credential access": [
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter*",
            "kms:Decrypt",
            "iam:ListAccessKeys",
            "iam:GetLoginProfile",
        ],
        "Data exfiltration": [
            "s3:GetObject",
            "s3:ListBucket",
            "s3:PutBucketPolicy",
            "dynamodb:Scan",
            "rds:DescribeDBInstances",
        ],
    }

    def run(self):
        try:
            print_info("Starting IAM attack surface mapping...")
            identity = self._aws_json("aws sts get-caller-identity 2>/dev/null")
            if not identity:
                print_error("Could not resolve caller identity")
                return False

            arn = identity.get("Arn", "")
            print_info(f"Principal: {arn}")

            policy_docs = self._collect_policies_for_current_principal(arn)
            if not policy_docs:
                print_warning("No readable IAM policy document found for current principal")
                return True

            findings = self._analyze_policy_documents(policy_docs)
            self._print_findings(findings, len(policy_docs))
            return True
        except Exception as e:
            print_error(f"Error during IAM attack surface mapping: {e}")
            return False

    def _aws_json(self, cmd):
        out = (self.cmd_execute(cmd) or "").strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except Exception:
            if self.verbose:
                print_warning(f"Command did not return JSON: {cmd}")
                print_info(out)
            return None

    def _collect_policies_for_current_principal(self, arn):
        docs = []

        # arn:aws:iam::123456789012:user/alice
        if ":user/" in arn:
            username = arn.split(":user/", 1)[1]
            print_info(f"Detected IAM user principal: {username}")
            if self.include_managed:
                docs.extend(self._get_user_managed_policy_docs(username))
            if self.include_inline:
                docs.extend(self._get_user_inline_policy_docs(username))
            return docs

        # arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
        if ":assumed-role/" in arn:
            role_part = arn.split(":assumed-role/", 1)[1]
            role_name = role_part.split("/", 1)[0]
            print_info(f"Detected assumed role principal: {role_name}")
            if self.include_managed:
                docs.extend(self._get_role_managed_policy_docs(role_name))
            if self.include_inline:
                docs.extend(self._get_role_inline_policy_docs(role_name))
            return docs

        # arn:aws:iam::123456789012:role/RoleName
        if ":role/" in arn:
            role_name = arn.split(":role/", 1)[1]
            print_info(f"Detected IAM role principal: {role_name}")
            if self.include_managed:
                docs.extend(self._get_role_managed_policy_docs(role_name))
            if self.include_inline:
                docs.extend(self._get_role_inline_policy_docs(role_name))
            return docs

        print_warning("Principal type unsupported for automatic policy collection")
        return docs

    def _get_user_managed_policy_docs(self, username):
        docs = []
        attached = self._aws_json(
            f"aws iam list-attached-user-policies --user-name {username} 2>/dev/null"
        ) or {}
        policies = attached.get("AttachedPolicies", [])

        for p in policies:
            arn = p.get("PolicyArn", "")
            name = p.get("PolicyName", arn)
            doc = self._fetch_managed_policy_document(arn)
            if doc:
                docs.append({"source": f"user-attached:{name}", "document": doc})
        return docs

    def _get_role_managed_policy_docs(self, role_name):
        docs = []
        attached = self._aws_json(
            f"aws iam list-attached-role-policies --role-name {role_name} 2>/dev/null"
        ) or {}
        policies = attached.get("AttachedPolicies", [])

        for p in policies:
            arn = p.get("PolicyArn", "")
            name = p.get("PolicyName", arn)
            doc = self._fetch_managed_policy_document(arn)
            if doc:
                docs.append({"source": f"role-attached:{name}", "document": doc})
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

    def _get_user_inline_policy_docs(self, username):
        docs = []
        data = self._aws_json(f"aws iam list-user-policies --user-name {username} 2>/dev/null") or {}
        for name in data.get("PolicyNames", []):
            pol = self._aws_json(
                f"aws iam get-user-policy --user-name {username} --policy-name {name} 2>/dev/null"
            )
            doc = (pol or {}).get("PolicyDocument")
            if doc:
                docs.append({"source": f"user-inline:{name}", "document": doc})
        return docs

    def _get_role_inline_policy_docs(self, role_name):
        docs = []
        data = self._aws_json(f"aws iam list-role-policies --role-name {role_name} 2>/dev/null") or {}
        for name in data.get("PolicyNames", []):
            pol = self._aws_json(
                f"aws iam get-role-policy --role-name {role_name} --policy-name {name} 2>/dev/null"
            )
            doc = (pol or {}).get("PolicyDocument")
            if doc:
                docs.append({"source": f"role-inline:{name}", "document": doc})
        return docs

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _matches_pattern(self, action, pattern):
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())

    def _analyze_policy_documents(self, policy_docs):
        findings = {}
        for category in self.DANGEROUS_PATTERNS:
            findings[category] = []

        for item in policy_docs:
            source = item.get("source", "unknown")
            doc = item.get("document", {})
            statements = self._as_list((doc or {}).get("Statement"))

            for stmt in statements:
                effect = str(stmt.get("Effect", "")).lower()
                if effect != "allow":
                    continue
                if "NotAction" in stmt:
                    continue

                actions = self._as_list(stmt.get("Action"))
                for category, patterns in self.DANGEROUS_PATTERNS.items():
                    matched = []
                    for action in actions:
                        for patt in patterns:
                            if self._matches_pattern(str(action), patt):
                                matched.append(str(action))
                                break
                    if matched:
                        findings[category].append({
                            "source": source,
                            "actions": sorted(set(matched))
                        })

        return findings

    def _print_findings(self, findings, policy_count):
        print_info("=" * 80)
        print_info(f"Analyzed {policy_count} policy document(s)")
        total = 0

        for category, items in findings.items():
            # Deduplicate source/action combinations
            unique = {}
            for it in items:
                key = (it["source"], tuple(it["actions"]))
                unique[key] = it
            entries = list(unique.values())

            if not entries:
                print_success(f"{category}: no dangerous permission pattern detected")
                continue

            total += len(entries)
            print_warning(f"{category}: {len(entries)} finding(s)")
            for e in entries[:15]:
                print_info(f"  - source={e['source']}")
                if self.verbose:
                    print_info(f"    actions={', '.join(e['actions'])}")
            if len(entries) > 15:
                print_info(f"  ... and {len(entries) - 15} more")

        print_info("-" * 80)
        if total == 0:
            print_success("No high-risk permission pattern found in analyzed policies")
        else:
            print_warning(f"Total high-risk findings: {total}")
