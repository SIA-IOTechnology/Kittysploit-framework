#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json
import fnmatch


class Module(Post):
    __info__ = {
        "name": "Cloud Misconfig Chains",
        "description": "Correlate AWS misconfigurations into practical compromise chains.",
        "author": "KittySploit Team",
        "session_type": SessionType.AWS,
    }

    include_trust_analysis = OptBool(True, "Analyze role trust policies", False)
    include_s3 = OptBool(True, "Analyze S3 public/risky bucket posture", False)
    max_roles = OptString("60", "Maximum roles to inspect", False)
    output_file = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show detailed permission evidence", False)

    CHAIN_RULES = [
        {
            "id": "lambda_passrole_admin",
            "name": "PassRole + Lambda write chain",
            "requires_any": ["iam:PassRole"],
            "requires_all": ["lambda:CreateFunction"],
            "impact": "Create or modify Lambda with privileged role, then execute arbitrary code.",
            "severity": "HIGH",
        },
        {
            "id": "iam_policy_takeover",
            "name": "IAM policy takeover chain",
            "requires_any": ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
            "requires_all": [],
            "impact": "Attach elevated policy then escalate to administrative control.",
            "severity": "HIGH",
        },
        {
            "id": "assumerole_chain",
            "name": "Wildcard AssumeRole chain",
            "requires_any": [],
            "requires_all": ["sts:AssumeRole"],
            "impact": "Pivot laterally across roles and accounts through trust abuse.",
            "severity": "MEDIUM",
        },
        {
            "id": "secrets_exfil_chain",
            "name": "Secrets + decrypt chain",
            "requires_any": ["secretsmanager:GetSecretValue", "ssm:GetParameter*", "kms:Decrypt"],
            "requires_all": [],
            "impact": "Extract plaintext secrets and re-use credentials for deeper compromise.",
            "severity": "MEDIUM",
        },
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _aws_json(self, cmd):
        try:
            out = self.session.cmd_exec(f"{cmd} --output json 2>/dev/null")
            if not out:
                return {}
            return json.loads(out)
        except Exception:
            return {}

    def _collect_actions(self):
        identity = self._aws_json("aws sts get-caller-identity")
        arn = identity.get("Arn", "")
        if not arn:
            return "", set()

        actions = set()
        # For MVP chaining, gather from attached managed policies of current role/user when accessible.
        if ":user/" in arn:
            name = arn.split("/")[-1]
            attached = self._aws_json(f"aws iam list-attached-user-policies --user-name {name}")
            for p in attached.get("AttachedPolicies", []):
                doc = self._managed_policy_document(p.get("PolicyArn"))
                actions |= self._extract_actions(doc)
        elif ":assumed-role/" in arn or ":role/" in arn:
            role_name = arn.split("/")[-2] if ":assumed-role/" in arn else arn.split("/")[-1]
            attached = self._aws_json(f"aws iam list-attached-role-policies --role-name {role_name}")
            for p in attached.get("AttachedPolicies", []):
                doc = self._managed_policy_document(p.get("PolicyArn"))
                actions |= self._extract_actions(doc)
        return arn, actions

    def _managed_policy_document(self, arn):
        if not arn:
            return {}
        p = self._aws_json(f"aws iam get-policy --policy-arn {arn}")
        version = (((p.get("Policy") or {}).get("DefaultVersionId")) or "").strip()
        if not version:
            return {}
        v = self._aws_json(f"aws iam get-policy-version --policy-arn {arn} --version-id {version}")
        return ((v.get("PolicyVersion") or {}).get("Document")) or {}

    def _extract_actions(self, policy_doc):
        actions = set()
        stmts = policy_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if str(st.get("Effect", "Allow")).lower() != "allow":
                continue
            raw = st.get("Action", [])
            if isinstance(raw, str):
                raw = [raw]
            for a in raw:
                if isinstance(a, str):
                    actions.add(a)
        return actions

    def _has_action(self, effective_actions, expected):
        exp = str(expected).strip()
        for a in effective_actions:
            if fnmatch.fnmatchcase(a.lower(), exp.lower()):
                return True
        return False

    def _evaluate_chains(self, effective_actions):
        findings = []
        for r in self.CHAIN_RULES:
            any_ok = True
            all_ok = True
            any_hits = []
            all_hits = []

            if r.get("requires_any"):
                any_ok = False
                for pat in r["requires_any"]:
                    if self._has_action(effective_actions, pat):
                        any_ok = True
                        any_hits.append(pat)
            for pat in r.get("requires_all", []):
                if self._has_action(effective_actions, pat):
                    all_hits.append(pat)
                else:
                    all_ok = False

            if any_ok and all_ok:
                conf = 70 + min(20, (len(any_hits) * 5) + (len(all_hits) * 5))
                findings.append({
                    "id": r["id"],
                    "name": r["name"],
                    "severity": r["severity"],
                    "impact": r["impact"],
                    "confidence": conf,
                    "evidence_any": any_hits,
                    "evidence_all": all_hits,
                })
        return sorted(findings, key=lambda x: (x.get("severity") == "HIGH", x.get("confidence", 0)), reverse=True)

    def run(self):
        print_info("Analyzing cloud misconfiguration chains...")
        arn, actions = self._collect_actions()
        if not arn:
            print_error("Unable to resolve current AWS identity.")
            return False

        findings = self._evaluate_chains(actions)
        risk_score = min(10, sum(3 if f["severity"] == "HIGH" else 2 for f in findings))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")

        result = {
            "principal_arn": arn,
            "effective_actions_count": len(actions),
            "count": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
        }

        print_success(f"Cloud chains: {len(findings)} finding(s), risk={risk_level}/{risk_score}")
        for i, f in enumerate(findings[:12], 1):
            print_warning(f"  {i}. [{f['severity']}] {f['name']} (confidence={f['confidence']})")
            if self.verbose:
                print_info(f"      impact: {f['impact']}")
                if f.get("evidence_any"):
                    print_info(f"      any: {', '.join(f['evidence_any'])}")
                if f.get("evidence_all"):
                    print_info(f"      all: {', '.join(f['evidence_all'])}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(result, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return result
