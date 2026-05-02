#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json


class Module(Post):
    __info__ = {
        "name": "AWS Security Posture",
        "description": "Audit AWS account security posture (IAM, root safeguards, MFA, and S3 public exposure)",
        "author": "KittySploit Team",
        "session_type": SessionType.AWS,
    }

    check_iam_summary = OptBool(True, "Check IAM account summary and root safeguards", False)
    check_password_policy = OptBool(True, "Check IAM password policy", False)
    check_users_mfa = OptBool(True, "Check IAM users without MFA", False)
    check_s3_exposure = OptBool(True, "Check S3 bucket public exposure indicators", False)
    max_users = OptString("30", "Maximum IAM users to inspect for MFA checks", False)
    max_buckets = OptString("30", "Maximum S3 buckets to inspect for exposure checks", False)
    verbose = OptBool(False, "Show additional diagnostic output", False)

    def run(self):
        try:
            print_info("Starting AWS security posture audit...")
            identity = self._get_caller_identity()
            if identity:
                print_info(f"Caller identity: {identity.get('Arn', 'Unknown')}")
                print_info(f"Account: {identity.get('Account', 'Unknown')}")
            else:
                print_warning("Could not resolve caller identity (AWS CLI/boto credentials may be missing)")

            print_info("=" * 80)

            if self.check_iam_summary:
                self._check_iam_summary()
            if self.check_password_policy:
                self._check_password_policy()
            if self.check_users_mfa:
                self._check_users_mfa()
            if self.check_s3_exposure:
                self._check_s3_exposure()

            print_info("=" * 80)
            print_success("AWS security posture audit completed")
            return True
        except Exception as e:
            print_error(f"Error during AWS posture audit: {e}")
            return False

    def _to_int(self, value, default):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default

    def _run_cmd(self, cmd):
        return (self.cmd_execute(cmd) or "").strip()

    def _aws_json(self, cmd):
        output = self._run_cmd(cmd)
        if not output:
            return None
        try:
            return json.loads(output)
        except Exception:
            if self.verbose:
                print_warning(f"Non-JSON output for command: {cmd}")
                print_info(output)
            return None

    def _get_caller_identity(self):
        return self._aws_json("aws sts get-caller-identity 2>/dev/null")

    def _check_iam_summary(self):
        print_status("Check: IAM account summary")
        summary = self._aws_json("aws iam get-account-summary 2>/dev/null")
        if not summary:
            print_warning("Could not read IAM account summary")
            print_info("-" * 80)
            return

        m = summary.get("SummaryMap", {})
        users = m.get("Users", 0)
        roles = m.get("Roles", 0)
        groups = m.get("Groups", 0)
        policies = m.get("Policies", 0)
        root_mfa = m.get("AccountMFAEnabled", 0)
        root_keys = m.get("AccountAccessKeysPresent", 0)

        print_info(f"Users={users}, Roles={roles}, Groups={groups}, CustomerPolicies={policies}")

        if root_mfa == 1:
            print_success("Root account MFA is enabled")
        else:
            print_error("Root account MFA is NOT enabled")

        if root_keys == 0:
            print_success("No root access key present")
        else:
            print_error("Root access key is present")

        print_info("-" * 80)

    def _check_password_policy(self):
        print_status("Check: IAM password policy")
        policy_data = self._aws_json("aws iam get-account-password-policy 2>/dev/null")
        if not policy_data:
            print_warning("No account password policy found or access denied")
            print_info("-" * 80)
            return

        policy = policy_data.get("PasswordPolicy", {})
        min_len = policy.get("MinimumPasswordLength", 0)
        reuse_prevention = policy.get("PasswordReusePrevention", 0)
        max_age = policy.get("MaxPasswordAge", 0)
        hard_expiry = policy.get("HardExpiry", False)
        require_symbols = policy.get("RequireSymbols", False)
        require_numbers = policy.get("RequireNumbers", False)
        require_upper = policy.get("RequireUppercaseCharacters", False)
        require_lower = policy.get("RequireLowercaseCharacters", False)
        mfa_required = policy.get("RequireMFA", None)

        print_info(f"MinimumPasswordLength={min_len}")
        if min_len >= 12:
            print_success("Password minimum length is >= 12")
        else:
            print_warning("Password minimum length is weak (< 12)")

        complexity = all([require_symbols, require_numbers, require_upper, require_lower])
        if complexity:
            print_success("Password complexity requirements are enabled")
        else:
            print_warning("Password complexity requirements are not fully enabled")

        if reuse_prevention and int(reuse_prevention) >= 5:
            print_success(f"PasswordReusePrevention={reuse_prevention}")
        else:
            print_warning(f"PasswordReusePrevention={reuse_prevention} (recommended >= 5)")

        if max_age and int(max_age) <= 90:
            print_success(f"MaxPasswordAge={max_age} days")
        else:
            print_warning(f"MaxPasswordAge={max_age} (recommended <= 90)")

        if hard_expiry:
            print_warning("HardExpiry is enabled (can impact operational access workflows)")
        elif self.verbose:
            print_info("HardExpiry is disabled")

        if mfa_required is not None:
            if mfa_required:
                print_success("Console password policy indicates MFA required")
            else:
                print_warning("Console password policy does not enforce MFA")

        print_info("-" * 80)

    def _check_users_mfa(self):
        print_status("Check: IAM users MFA coverage")
        data = self._aws_json("aws iam list-users 2>/dev/null")
        if not data:
            print_warning("Could not list IAM users")
            print_info("-" * 80)
            return

        users = data.get("Users", [])
        if not users:
            print_success("No IAM users found")
            print_info("-" * 80)
            return

        max_users = self._to_int(self.max_users, 30)
        sample = users[:max_users]
        without_mfa = []

        for u in sample:
            username = u.get("UserName")
            if not username:
                continue
            mfa = self._aws_json(f"aws iam list-mfa-devices --user-name {username} 2>/dev/null")
            devices = (mfa or {}).get("MFADevices", [])
            if len(devices) == 0:
                without_mfa.append(username)

        print_info(f"Scanned {len(sample)}/{len(users)} IAM users for MFA")
        if without_mfa:
            print_warning(f"Users without MFA ({len(without_mfa)}):")
            for name in without_mfa[:20]:
                print_info(f"  - {name}")
            if len(without_mfa) > 20:
                print_info(f"  ... and {len(without_mfa) - 20} more")
        else:
            print_success("All scanned IAM users have MFA devices")

        print_info("-" * 80)

    def _check_s3_exposure(self):
        print_status("Check: S3 public exposure indicators")
        data = self._aws_json("aws s3api list-buckets 2>/dev/null")
        if not data:
            print_warning("Could not list S3 buckets")
            print_info("-" * 80)
            return

        buckets = data.get("Buckets", [])
        if not buckets:
            print_success("No S3 buckets found")
            print_info("-" * 80)
            return

        max_buckets = self._to_int(self.max_buckets, 30)
        sample = buckets[:max_buckets]
        risky = []

        for b in sample:
            name = b.get("Name")
            if not name:
                continue

            pab = self._aws_json(
                f"aws s3api get-public-access-block --bucket {name} 2>/dev/null"
            )
            acl = self._aws_json(f"aws s3api get-bucket-acl --bucket {name} 2>/dev/null")

            pab_cfg = (pab or {}).get("PublicAccessBlockConfiguration", {})
            block_public = (
                pab_cfg.get("BlockPublicAcls", False)
                and pab_cfg.get("IgnorePublicAcls", False)
                and pab_cfg.get("BlockPublicPolicy", False)
                and pab_cfg.get("RestrictPublicBuckets", False)
            )

            public_grant = False
            grants = (acl or {}).get("Grants", [])
            for grant in grants:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_grant = True
                    break

            if (not block_public) or public_grant:
                risky.append({
                    "bucket": name,
                    "block_public_access_fully_enabled": block_public,
                    "public_acl_grant_detected": public_grant
                })

        print_info(f"Scanned {len(sample)}/{len(buckets)} buckets")
        if risky:
            print_warning(f"Buckets with potential exposure ({len(risky)}):")
            for item in risky[:20]:
                print_info(
                    f"  - {item['bucket']} | block_public_access={item['block_public_access_fully_enabled']} "
                    f"| public_acl={item['public_acl_grant_detected']}"
                )
            if len(risky) > 20:
                print_info(f"  ... and {len(risky) - 20} more")
        else:
            print_success("No obvious S3 public exposure found in scanned buckets")

        print_info("-" * 80)
