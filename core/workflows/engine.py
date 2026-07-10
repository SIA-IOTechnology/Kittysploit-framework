#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.framework.workflow import Workflow, WorkflowStep
from core.framework.module_context import capture_module_context, restore_module_context
from core.output_handler import print_error, print_info, print_success, print_warning
from core.scanner.probe_failure import is_soft_probe_failure
from core.workflows.definition import WorkflowDefinition, WorkflowStepDefinition, WorkflowVariableSpec

_VAR_PATTERN = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _is_soft_probe_failure(exc: Exception) -> bool:
    return is_soft_probe_failure(exc)


@dataclass
class WorkflowRunResult:
    workflow_id: str
    success: bool
    dry_run: bool
    duration_seconds: float
    steps_executed: List[str] = field(default_factory=list)
    step_results: Dict[str, Any] = field(default_factory=dict)
    context_data: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    plan: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def matches(self) -> int:
        return sum(1 for value in (self.step_results or {}).values() if value)


class WorkflowEngine:
    """Build and run declarative workflows on top of WorkflowStep."""

    def __init__(self, framework):
        self.framework = framework

    def resolve_variables(
        self,
        definition: WorkflowDefinition,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        overrides = dict(overrides or {})
        resolved: Dict[str, str] = {}

        for name, spec in definition.variables.items():
            if name in overrides and overrides[name] is not None:
                resolved[name] = str(overrides[name])
            elif spec.default is not None:
                resolved[name] = spec.default
            elif spec.required:
                raise ValueError(f"Missing required workflow variable: {name}")

        for name, value in overrides.items():
            if value is not None and name not in resolved:
                resolved[name] = str(value)

        from lib.scanner.target_utils import apply_url_target_to_variables

        return apply_url_target_to_variables(resolved)

    def build_workflow(
        self,
        definition: WorkflowDefinition,
        variables: Dict[str, str],
    ) -> Workflow:
        workflow = Workflow(self.framework)
        workflow.name = definition.name
        workflow.description = definition.description
        workflow.author = "KittySploit Workflow Library"
        workflow.start_step = definition.start_step

        for step_name, step_def in definition.steps.items():
            workflow.add_step(self._build_step(step_def, variables))

        if definition.start_step:
            workflow.set_start_step(definition.start_step)
        return workflow

    def run(
        self,
        definition: WorkflowDefinition,
        variables: Optional[Dict[str, Any]] = None,
        *,
        dry_run: bool = False,
    ) -> WorkflowRunResult:
        resolved = self.resolve_variables(definition, variables)
        started = time.time()
        plan = self._build_plan(definition, resolved)

        if dry_run:
            return WorkflowRunResult(
                workflow_id=definition.workflow_id,
                success=True,
                dry_run=True,
                duration_seconds=time.time() - started,
                plan=plan,
                context_data=dict(resolved),
            )

        previous_module = capture_module_context(self.framework)
        try:
            context = {
                "start_time": started,
                "results": {},
                "current_step": definition.start_step,
                "data": dict(resolved),
            }
            executed: List[str] = []
            step_results: Dict[str, Any] = {}
            errors: Dict[str, str] = {}
            current = definition.start_step
            overall_success = True
            quiet_probes = bool(definition.policy.get("quiet_probes"))

            while current:
                step_def = definition.steps.get(current)
                if not step_def:
                    errors[current] = "Step not found in workflow definition"
                    overall_success = False
                    break

                if step_def.when and not self._eval_when(step_def.when, context["data"]):
                    print_info(f"Step {current} skipped (when={step_def.when})")
                    current = step_def.on_success
                    continue

                if not quiet_probes:
                    print_info(f"Executing step: {current} — {step_def.description or step_def.name}")
                executed.append(current)

                try:
                    if step_def.step_type == "builtin":
                        ok = self._run_builtin(step_def, context, resolved)
                    else:
                        ok = self._run_module_step(step_def, context, resolved)
                    step_results[current] = ok
                    context["results"][current] = ok
                    if ok:
                        label = step_def.description or step_def.name or current
                        print_success(f"Match: {current} — {label}")
                        current = step_def.on_success
                    else:
                        if not quiet_probes and not definition.continue_on_failure:
                            print_warning(f"Step {current} failed")
                        overall_success = False
                        if definition.continue_on_failure and step_def.on_failure:
                            current = step_def.on_failure
                        elif definition.continue_on_failure and step_def.on_success:
                            current = step_def.on_success
                        else:
                            current = step_def.on_failure
                except Exception as exc:
                    step_results[current] = False
                    context["results"][current] = False
                    overall_success = False
                    if _is_soft_probe_failure(exc):
                        if not quiet_probes and not definition.continue_on_failure:
                            print_warning(f"Step {current} failed")
                        if definition.continue_on_failure and step_def.on_failure:
                            current = step_def.on_failure
                        elif definition.continue_on_failure and step_def.on_success:
                            current = step_def.on_success
                        else:
                            current = step_def.on_failure
                    else:
                        msg = str(exc)
                        errors[current] = msg
                        print_error(f"Step {current} error: {msg}")
                        current = step_def.on_failure

            if definition.continue_on_failure:
                workflow_success = not errors
            else:
                workflow_success = overall_success and not errors

            return WorkflowRunResult(
                workflow_id=definition.workflow_id,
                success=workflow_success,
                dry_run=False,
                duration_seconds=time.time() - started,
                steps_executed=executed,
                step_results=step_results,
                context_data=dict(context.get("data") or {}),
                errors=errors,
                plan=plan,
            )
        finally:
            restore_module_context(self.framework, previous_module)

    def _build_plan(
        self,
        definition: WorkflowDefinition,
        variables: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        plan: List[Dict[str, Any]] = []
        for name, step in definition.steps.items():
            entry: Dict[str, Any] = {
                "name": name,
                "type": step.step_type,
                "description": step.description,
                "on_success": step.on_success,
                "on_failure": step.on_failure,
            }
            if step.step_type == "builtin":
                entry["action"] = step.builtin_action
            else:
                entry["module"] = step.module
                entry["options"] = self._substitute_mapping(step.options, variables)
            if step.when:
                entry["when"] = step.when
            plan.append(entry)
        return plan

    def _build_step(self, step_def: WorkflowStepDefinition, variables: Dict[str, str]) -> WorkflowStep:
        options = self._substitute_mapping(step_def.options, variables)
        step = WorkflowStep(
            module_path=step_def.module or "",
            options=options,
            name=step_def.name,
            description=step_def.description,
            on_success=step_def.on_success,
            on_failure=step_def.on_failure,
        )
        for module_attr, context_key in step_def.output_mapping.items():
            step.map_output(module_attr, context_key)
        for context_key, module_option in step_def.input_mapping.items():
            step.map_input(context_key, module_option)
        return step

    def _run_module_step(
        self,
        step_def: WorkflowStepDefinition,
        context: Dict[str, Any],
        variables: Dict[str, str],
    ) -> bool:
        if not step_def.module:
            raise ValueError(f"Module step '{step_def.name}' has no module path")

        module = self.framework.load_module(step_def.module)
        if not module:
            raise RuntimeError(f"Unable to load module: {step_def.module}")

        options = self._substitute_mapping(step_def.options, {**variables, **context["data"]})
        for option_name, option_value in options.items():
            if hasattr(module, option_name):
                setattr(module, option_name, self._coerce_option(option_value))

        if step_def.input_mapping:
            step = WorkflowStep(module_path=step_def.module)
            for context_key, module_option in step_def.input_mapping.items():
                step.input_mapping = getattr(step, "input_mapping", None) or {}
                step.map_input(context_key, module_option)
            step.apply_inputs(module, context["data"])

        result = module.run()

        if step_def.output_mapping:
            step = WorkflowStep(module_path=step_def.module)
            for module_attr, context_key in step_def.output_mapping.items():
                step.map_output(module_attr, context_key)
            outputs = step.extract_outputs(module)
            context["data"].update(outputs)

        if "osint/" in str(step_def.module or ""):
            from core.osint.evidence import envelope_osint_details
            from core.osint.opsec import OsintOpsecJournal

            journal = context.setdefault(
                "_osint_opsec_journal",
                OsintOpsecJournal(
                    case_id=str(context["data"].get("target") or ""),
                    legal_basis=str(context["data"].get("legal_basis") or ""),
                    passive_only=True,
                ),
            )
            violation = journal.check_passive_violation(str(step_def.module or ""))
            if violation:
                print_warning(violation)
                return False

            osint_results = context.setdefault("osint_module_results", [])
            details = result if isinstance(result, dict) else {}
            target = str(context["data"].get("target", ""))
            row = {
                "module": step_def.module,
                "path": step_def.module,
                "status": "error" if isinstance(details, dict) and details.get("error") else "safe",
                "target": target,
                "details": envelope_osint_details(
                    details,
                    module_path=str(step_def.module or ""),
                    target=target,
                ),
            }
            osint_results.append(row)
            journal.record(
                action="module_complete",
                module=str(step_def.module or ""),
                target=target,
                status=str(row.get("status") or "ok"),
            )

        return bool(result)

    def _run_builtin(
        self,
        step_def: WorkflowStepDefinition,
        context: Dict[str, Any],
        variables: Dict[str, str],
    ) -> bool:
        action = (step_def.builtin_action or "").strip().lower()
        if action == "workspace_primary_target":
            existing = (context["data"].get("target") or variables.get("target") or "").strip()
            if existing:
                context["data"]["target"] = existing
                context["data"]["primary_target"] = existing
                print_info(f"Using provided target: {existing}")
                return True
            target = resolve_workspace_primary_target(self.framework)
            if not target:
                print_warning("No workspace host found for primary target")
                return False
            context["data"]["target"] = target
            context["data"]["primary_target"] = target
            print_info(f"Workspace primary target: {target}")
            return True
        if action == "purple_export":
            output_dir = Path(
                self._substitute_string(
                    step_def.options.get("output_dir", "artifacts/purple/${workflow_id}"),
                    {**variables, **context["data"], "workflow_id": variables.get("workflow_id", "")},
                )
            )
            return write_purple_export_bundle(self.framework, output_dir, context["data"])
        if action == "osint_evidence_export":
            output_dir = Path(
                self._substitute_string(
                    step_def.options.get("output_dir", "artifacts/osint/${target}"),
                    {**variables, **context["data"]},
                )
            )
            return write_osint_evidence_export_bundle(
                output_dir,
                context,
                legal_basis=self._substitute_string(
                    str(step_def.options.get("legal_basis", "")),
                    {**variables, **context["data"]},
                ),
                tlp=self._substitute_string(
                    str(step_def.options.get("tlp", "AMBER")),
                    {**variables, **context["data"]},
                ),
                retention_days=self._substitute_string(
                    str(step_def.options.get("retention_days", "90")),
                    {**variables, **context["data"]},
                ),
                data_controller=self._substitute_string(
                    str(step_def.options.get("data_controller", "")),
                    {**variables, **context["data"]},
                ),
                recipient_org=self._substitute_string(
                    str(step_def.options.get("recipient_org", "")),
                    {**variables, **context["data"]},
                ),
            )
        if action == "client_retest_summary":
            return write_client_retest_summary(
                self.framework,
                Path(
                    self._substitute_string(
                        step_def.options.get("output_dir", "artifacts/retest"),
                        {**variables, **context["data"]},
                    )
                ),
                context,
            )
        raise ValueError(f"Unknown builtin workflow action: {action}")

    def _substitute_mapping(self, data: Dict[str, Any], variables: Dict[str, str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in (data or {}).items():
            if isinstance(value, str):
                out[key] = self._substitute_string(value, variables)
            elif isinstance(value, dict):
                out[key] = self._substitute_mapping(value, variables)
            else:
                out[key] = value
        return out

    def _substitute_string(self, value: str, variables: Dict[str, str]) -> str:
        def repl(match: re.Match) -> str:
            key = match.group(1)
            return variables.get(key, match.group(0))

        return _VAR_PATTERN.sub(repl, value)

    def _coerce_option(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        low = value.strip().lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
            return False
        if low.isdigit():
            return int(low)
        try:
            if "." in low:
                return float(low)
        except ValueError:
            pass
        return value

    def _eval_when(self, expression: str, data: Dict[str, Any]) -> bool:
        expr = expression.strip()
        if "==" in expr:
            left, right = [part.strip() for part in expr.split("==", 1)]
            left_key = left.replace("${", "").replace("}", "")
            return str(data.get(left_key, "")) == right.strip().strip("'\"")
        key = expr.replace("${", "").replace("}", "")
        return bool(data.get(key))


def resolve_workspace_primary_target(framework) -> Optional[str]:
    wm = getattr(framework, "workspace_manager", None)
    db = getattr(framework, "db_manager", None)
    if not wm or not db:
        return None

    current = wm.get_current_workspace()
    if not current:
        return None

    session = db.get_session("default")
    if not session:
        return None

    from core.models.models import Host

    hosts = (
        session.query(Host)
        .filter(Host.workspace_id == current.id)
        .order_by(Host.id.asc())
        .all()
    )
    if not hosts:
        return None

    host = hosts[0]
    address = (host.address or "").strip()
    if not address:
        return None

    for service in host.services or []:
        port = getattr(service, "port", None)
        name = (getattr(service, "name", "") or "").lower()
        if port in (80, 443, 8080, 8443) or "http" in name:
            scheme = "https" if port in (443, 8443) else "http"
            port_suffix = "" if port in (80, 443) else f":{port}"
            return f"{scheme}://{address}{port_suffix}/"

    if address.startswith("http://") or address.startswith("https://"):
        return address
    return address


def write_osint_evidence_export_bundle(
    output_dir: Path,
    context: Dict[str, Any],
    *,
    legal_basis: str = "",
    tlp: str = "AMBER",
    retention_days: str = "90",
    data_controller: str = "",
    recipient_org: str = "",
) -> bool:
    from core.osint.gdpr import OsintRetentionPolicy
    from core.osint.intel_synthesis import synthesize_intel_graph
    from core.osint.password_profiling import organization_root_domain
    from core.osint.persist import write_osint_evidence_bundle

    data = dict(context.get("data") or {})
    module_results = list(context.get("osint_module_results") or [])
    target = str(data.get("target") or "")
    root = organization_root_domain(target)
    persona = str(data.get("persona_name") or "")

    identities = {"emails": [], "handles": [], "names": []}
    if persona:
        identities["names"].append(persona)
    for row in module_results:
        details = row.get("details") if isinstance(row, dict) else {}
        if not isinstance(details, dict):
            continue
        for email in details.get("emails") or []:
            identities["emails"].append(str(email))
        for finding in details.get("findings") or []:
            if isinstance(finding, dict) and finding.get("handle"):
                identities["handles"].append(str(finding["handle"]))

    synthesis = synthesize_intel_graph(
        module_results,
        root_domain=root,
        identities=identities,
        persona_seed=persona,
    )
    try:
        pii_days = max(1, int(str(retention_days or "90").strip()))
    except ValueError:
        pii_days = OsintRetentionPolicy.from_osint_config().pii_days
    base_policy = OsintRetentionPolicy.from_osint_config()
    policy = OsintRetentionPolicy(
        pii_days=pii_days,
        ioc_days=base_policy.ioc_days,
        audit_days=base_policy.audit_days,
        legal_basis_required=base_policy.legal_basis_required,
        pseudonymize_exports=base_policy.pseudonymize_exports,
        data_controller=data_controller or str(data.get("data_controller") or base_policy.data_controller),
        processing_purpose=base_policy.processing_purpose,
        lawful_basis_article=base_policy.lawful_basis_article,
    )
    paths = write_osint_evidence_bundle(
        module_results=module_results,
        synthesis=synthesis,
        output_dir=output_dir,
        run_id=str(data.get("workflow_id") or "workflow-osint"),
        legal_basis=legal_basis,
        target=root,
        tlp=tlp,
        actor="workflow",
        passive_only=True,
        opsec_journal=context.get("_osint_opsec_journal"),
        retention_policy=policy,
        data_controller=data_controller,
        recipient_org=recipient_org,
    )
    print_success(f"OSINT evidence bundle written to {output_dir} (manifest: {paths.get('manifest', '')})")
    return True


def write_purple_export_bundle(framework, output_dir: Path, context_data: Dict[str, Any]) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "type": "purple_export",
        "target": context_data.get("target"),
        "workflow": context_data.get("workflow_id"),
        "generated_at": time.time(),
        "notes": "Run detection_pack on individual modules for Sigma/YARA artifacts.",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    try:
        from core.attack_mapping import build_attack_catalog, export_stix_bundle

        discovered = {}
        loader = getattr(framework, "module_loader", None)
        if loader and hasattr(loader, "discover_modules"):
            discovered = loader.discover_modules() or {}
        catalog = build_attack_catalog(discovered)
        stix = export_stix_bundle(catalog)
        (output_dir / "attack_catalog.stix.json").write_text(
            json.dumps(stix, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        print_warning(f"STIX export skipped: {exc}")

    print_success(f"Purple export written to {output_dir}")
    return True


def write_client_retest_summary(framework, output_dir: Path, context: Dict[str, Any]) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "type": "client_retest",
        "generated_at": time.time(),
        "target": context.get("data", {}).get("target"),
        "step_results": context.get("results", {}),
    }
    (output_dir / "retest_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print_success(f"Client retest summary written to {output_dir}")
    return True
