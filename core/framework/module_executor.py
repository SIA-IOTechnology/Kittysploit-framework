#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Centralized module execution: preflight, dispatch, metrics, and jobs."""

from __future__ import annotations

import inspect
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.framework.runtime import EventType
from core.framework.base_module import ModuleResult, normalize_module_result
from core.framework.evidence_adapter import attach_schema_evidence


class ModuleExecutionBlockReason(Enum):
    MISSING_OPTIONS = "missing_options"
    SCOPE_DENIED = "scope_denied"
    GUARDIAN_BLACKLIST = "guardian_blacklist"


@dataclass
class PreflightResult:
    allowed: bool
    block_reason: Optional[ModuleExecutionBlockReason] = None
    missing_options: List[str] = field(default_factory=list)
    message: str = ""


@dataclass
class ModuleExecutionRequest:
    module: Any
    background: bool = False
    skip_scope_confirm: bool = False
    use_runtime_kernel: bool = False
    use_exploit_wrapper: bool = True
    collect_metrics: bool = True
    register_background_job: bool = False
    verbose_guardian_debug: bool = False


@dataclass
class ModuleExecutionResult:
    success: bool
    result: Any = None
    command_success: bool = True
    blocked: bool = False
    block_reason: Optional[ModuleExecutionBlockReason] = None
    missing_options: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    finding: Any = None
    evidence: Any = None
    schema_evidence: List[Dict[str, Any]] = field(default_factory=list)
    schema_finding: Optional[Dict[str, Any]] = None
    schema_validation_ok: bool = True
    schema_validation_errors: List[str] = field(default_factory=list)
    error: Optional[str] = None


class ModuleExecutor:
    """Single entry point for module preflight checks and execution."""

    @staticmethod
    def _coerce_module_result(raw: Any) -> ModuleResult:
        if isinstance(raw, ModuleResult):
            return raw
        return normalize_module_result(raw)

    @staticmethod
    def _execution_from_module_result(
        normalized: ModuleResult,
        *,
        command_success: Optional[bool] = None,
        raw_result: Any = None,
    ) -> ModuleExecutionResult:
        if command_success is None:
            command_success = normalized.success
        return ModuleExecutionResult(
            success=normalized.success,
            result=raw_result if raw_result is not None else normalized,
            command_success=command_success,
            session_id=normalized.session_id,
            finding=normalized.finding,
            evidence=normalized.evidence,
            error=normalized.error,
        )

    @staticmethod
    def get_module_type(module: Any) -> str:
        module_type = (
            getattr(module, "type", None)
            or getattr(module, "TYPE_MODULE", None)
            or getattr(module, "__info__", {}).get("type")
            or "module"
        )
        return str(module_type).lower()

    @staticmethod
    def is_payload(module: Any) -> bool:
        return ModuleExecutor.get_module_type(module) == "payload"

    @staticmethod
    def is_listener(module: Any) -> bool:
        return ModuleExecutor.get_module_type(module) == "listener"

    @staticmethod
    def is_scanner(module: Any) -> bool:
        return (
            getattr(module, "TYPE_MODULE", None) == "scanner"
            or ModuleExecutor.get_module_type(module) == "scanner"
        )

    @staticmethod
    def _emit(framework: Any, method: str, message: str) -> None:
        handler = getattr(framework, "output_handler", None)
        if handler and hasattr(handler, method):
            getattr(handler, method)(message)
            return
        from core.output_handler import (
            print_error,
            print_info,
            print_success,
            print_warning,
        )

        dispatch = {
            "print_error": print_error,
            "print_info": print_info,
            "print_success": print_success,
            "print_warning": print_warning,
        }
        dispatch[method](message)

    @staticmethod
    def validate_options(module: Any) -> Tuple[bool, List[str]]:
        try:
            if hasattr(module, "check_options") and not module.check_options():
                missing: List[str] = []
                if hasattr(module, "get_missing_options"):
                    missing = [str(item) for item in module.get_missing_options()]
                return False, missing
        except Exception:
            return False, []
        return True, []

    @staticmethod
    def check_guardian_blacklist(
        framework: Any,
        *,
        verbose_debug: bool = False,
    ) -> Tuple[bool, str]:
        guardian = getattr(framework, "guardian_manager", None)
        if not guardian or not getattr(guardian, "enabled", False):
            if verbose_debug and guardian:
                ModuleExecutor._emit(
                    framework,
                    "print_info",
                    f"[GUARDIAN DEBUG] guardian enabled: {guardian.enabled}",
                )
            return True, ""

        if verbose_debug:
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] Checking guardian - has guardian_manager: {hasattr(framework, 'guardian_manager')}",
            )
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] guardian_manager exists: {guardian is not None}",
            )
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] guardian_manager.enabled: {guardian.enabled}",
            )
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] blacklist size: {len(guardian.blacklist)}",
            )
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] blacklist contents: {list(guardian.blacklist.keys())}",
            )

        target_ip = None
        extractor = getattr(framework, "_extract_target_ip_from_module", None)
        if extractor:
            target_ip = extractor()

        if verbose_debug:
            ModuleExecutor._emit(
                framework,
                "print_info",
                f"[GUARDIAN DEBUG] Extracted target IP: {target_ip}",
            )
            if target_ip:
                ModuleExecutor._emit(
                    framework,
                    "print_info",
                    f"[GUARDIAN DEBUG] Is {target_ip} in blacklist? {target_ip in guardian.blacklist}",
                )

        if not target_ip:
            return True, ""

        if target_ip not in guardian.blacklist:
            return True, ""

        entry = guardian.blacklist[target_ip]
        reason = entry.get("reason", "Unknown reason")
        timestamp = entry.get("timestamp", "Unknown")
        message = (
            f"[GUARDIAN] Module execution BLOCKED: Target IP {target_ip} is blacklisted"
        )
        ModuleExecutor._emit(framework, "print_error", message)
        ModuleExecutor._emit(
            framework,
            "print_error",
            f"[GUARDIAN] Reason: {reason} (added: {timestamp})",
        )
        alert = guardian._create_alert(
            target=target_ip,
            severity="CRITICAL",
            issue=f"Module execution blocked: IP {target_ip} is blacklisted",
            confidence=100.0,
            recommendations=[
                "Remove IP from blacklist if this is intentional",
                "Verify target before removing from blacklist",
            ],
            evidence=[f"IP {target_ip} found in blacklist"],
        )
        alert.auto_action_taken = True
        alert.action_description = "Module execution blocked"
        return False, message

    @staticmethod
    def check_scope(
        framework: Any,
        module: Any,
        *,
        skip_confirm: bool = False,
    ) -> bool:
        manager = getattr(framework, "scope_manager", None)
        if not manager:
            return True
        return manager.ensure_execution_permitted(module, skip_confirm=skip_confirm)

    @staticmethod
    def run_preflight(
        framework: Any,
        module: Any,
        *,
        skip_scope_confirm: bool = False,
        verbose_guardian_debug: bool = False,
        check_options: bool = True,
    ) -> PreflightResult:
        if check_options:
            ok, missing = ModuleExecutor.validate_options(module)
            if not ok:
                if missing:
                    message = f"Missing required options: {', '.join(missing)}"
                else:
                    message = "Not all required options are set"
                return PreflightResult(
                    allowed=False,
                    block_reason=ModuleExecutionBlockReason.MISSING_OPTIONS,
                    missing_options=missing,
                    message=message,
                )

        if not ModuleExecutor.check_scope(
            framework,
            module,
            skip_confirm=skip_scope_confirm,
        ):
            return PreflightResult(
                allowed=False,
                block_reason=ModuleExecutionBlockReason.SCOPE_DENIED,
                message="Scope denied",
            )

        allowed, reason = ModuleExecutor.check_guardian_blacklist(
            framework,
            verbose_debug=verbose_guardian_debug,
        )
        if not allowed:
            return PreflightResult(
                allowed=False,
                block_reason=ModuleExecutionBlockReason.GUARDIAN_BLACKLIST,
                message=reason,
            )

        return PreflightResult(allowed=True)

    @staticmethod
    def _accepts_background(module: Any) -> bool:
        try:
            signature = inspect.signature(module.run)
            return "background" in signature.parameters
        except (ValueError, TypeError):
            return False

    @staticmethod
    def register_background_job(module: Any, framework: Any) -> Optional[int]:
        try:
            from core.job_manager import global_job_manager

            job_name = f"{module.type} {module.name}"
            if hasattr(module, "lhost") and hasattr(module, "lport"):
                host = str(module.lhost.value)
                port = int(module.lport.value)
                job_name = f"{module.type} {module.name} on {host}:{port}"

            job_id = global_job_manager.add_job(
                name=job_name,
                description=f"{module.type} module: {module.name}",
                module=module,
            )
            if job_id:
                ModuleExecutor._emit(
                    framework,
                    "print_success",
                    f"Module registered as background job [ID: {job_id}]",
                )
                if hasattr(module, "job_id"):
                    module.job_id = job_id
                return job_id

            ModuleExecutor._emit(
                framework,
                "print_warning",
                "Failed to register module as background job",
            )
        except Exception as exc:
            ModuleExecutor._emit(
                framework,
                "print_warning",
                f"Could not register module as background job: {exc}",
            )
        return None

    @staticmethod
    def _record_metrics(
        framework: Any,
        module: Any,
        duration: float,
        *,
        success: bool,
        error: Optional[str] = None,
    ) -> None:
        collector = getattr(framework, "metrics_collector", None)
        if not collector:
            return

        module_name = getattr(module, "name", "unknown")
        module_type = getattr(module, "module_type", "unknown")
        workspace = (
            framework.get_current_workspace_name()
            if hasattr(framework, "get_current_workspace_name")
            else "default"
        )
        observability = getattr(framework, "observability", None)
        correlation = (
            observability.correlation_metadata()
            if observability and observability.enabled
            else {}
        )
        metadata = {
            "module_name": module_name,
            "module_type": module_type,
            "workspace": workspace,
            **correlation,
        }
        collector.set_metadata_context(
            module_name=module_name,
            module_type=module_type,
            workspace=workspace,
        )
        collector.record_timing(
            "module.execution.duration",
            duration,
            metadata,
        )
        if success:
            collector.increment("module.execution.success", metadata=metadata)
        else:
            failure_meta = dict(metadata)
            if error:
                failure_meta["error"] = error
            collector.increment("module.execution.failure", metadata=failure_meta)
        collector.clear_metadata_context()

    @staticmethod
    def _reset_browser_auxiliary_flags(module: Any) -> None:
        try:
            from core.framework.browser_auxiliary import BrowserAuxiliary

            if isinstance(module, BrowserAuxiliary):
                module._reset_auto_return_flags()
        except ImportError:
            pass

    @staticmethod
    def _apply_browser_auxiliary_auto_return(module: Any, result: Any) -> Any:
        try:
            from core.framework.browser_auxiliary import BrowserAuxiliary

            if result is None and isinstance(module, BrowserAuxiliary):
                if (
                    hasattr(module, "_execute_js_called")
                    and module._execute_js_called
                ):
                    result = module._last_js_result
                    module._last_js_result = None
                    module._execute_js_called = False
        except ImportError:
            pass
        except Exception:
            pass
        return result

    @staticmethod
    def _create_listener_session(module: Any, result: Any, framework: Any) -> bool:
        if isinstance(result, tuple) and len(result) >= 3:
            connection, target, port = result[0], result[1], result[2]
            additional_data = result[3] if len(result) > 3 else {}
            if hasattr(module, "_create_session_from_connection_data"):
                session_id = module._create_session_from_connection_data(
                    connection,
                    target,
                    port,
                    additional_data,
                )
                if session_id:
                    ModuleExecutor._emit(
                        framework,
                        "print_success",
                        f"Session {session_id} created automatically",
                    )
                    return True
                ModuleExecutor._emit(
                    framework,
                    "print_error",
                    "Failed to create session automatically",
                )
                return False
            if hasattr(module, "run_with_auto_session"):
                session_id = module.run_with_auto_session()
                return bool(session_id)
            return False
        if isinstance(result, str) and result:
            ModuleExecutor._emit(
                framework,
                "print_success",
                f"Session {result} created",
            )
            return True
        if isinstance(result, ModuleResult):
            if result.session_id:
                ModuleExecutor._emit(
                    framework,
                    "print_success",
                    f"Session {result.session_id} created",
                )
                return True
            return result.success
        return bool(result) if result is not None else False

    @staticmethod
    def _execute_payload(module: Any) -> ModuleExecutionResult:
        try:
            payload_result = module.generate()
            if payload_result:
                return ModuleExecutionResult(
                    success=True,
                    result=payload_result,
                    command_success=True,
                )
            return ModuleExecutionResult(
                success=False,
                error="Failed to generate payload",
                command_success=False,
            )
        except Exception as exc:
            return ModuleExecutionResult(
                success=False,
                error=str(exc),
                command_success=False,
            )

    @staticmethod
    def _execute_listener(
        module: Any,
        framework: Any,
        request: ModuleExecutionRequest,
    ) -> ModuleExecutionResult:
        accepts_background = ModuleExecutor._accepts_background(module)

        if request.background:
            if accepts_background:
                result = module.run(background=True)
            else:
                result = module.run()
            success = ModuleExecutor._create_listener_session(module, result, framework)
            if success and request.register_background_job:
                ModuleExecutor.register_background_job(module, framework)
            normalized = ModuleExecutor._coerce_module_result(result)
            session_id = normalized.session_id
            if success and isinstance(result, str) and result.strip():
                session_id = result.strip()
            return ModuleExecutionResult(
                success=success,
                result=result,
                session_id=session_id,
                finding=normalized.finding,
                evidence=normalized.evidence,
                error=normalized.error if not success else None,
                command_success=success,
            )

        if hasattr(module, "run_with_auto_session"):
            result = module.run_with_auto_session()
            if isinstance(result, str) and result:
                return ModuleExecutionResult(
                    success=True,
                    result=result,
                    session_id=result,
                    command_success=True,
                )
            normalized = ModuleExecutor._coerce_module_result(result)
            session_id = normalized.session_id
            if session_id:
                return ModuleExecutor._execution_from_module_result(
                    normalized,
                    command_success=True,
                    raw_result=result,
                )
            success = normalized.success if result is not None else False
            return ModuleExecutor._execution_from_module_result(
                normalized,
                command_success=success,
                raw_result=result,
            )

        if accepts_background:
            result = module.run(background=False)
        else:
            result = module.run()
        normalized = ModuleExecutor._coerce_module_result(result)
        success = normalized.success if result is not None else False
        return ModuleExecutor._execution_from_module_result(
            normalized,
            command_success=success,
            raw_result=result,
        )

    @staticmethod
    def _execute_regular(
        module: Any,
        framework: Any,
        request: ModuleExecutionRequest,
    ) -> ModuleExecutionResult:
        if request.background:
            accepts_background = ModuleExecutor._accepts_background(module)
            if accepts_background:
                result = module.run(background=True)
            else:
                result = module.run()
            normalized = ModuleExecutor._coerce_module_result(result)
            success = normalized.success if result is not None else False
            if success and request.register_background_job:
                ModuleExecutor.register_background_job(module, framework)
            return ModuleExecutor._execution_from_module_result(
                normalized,
                command_success=success,
                raw_result=result,
            )

        ModuleExecutor._reset_browser_auxiliary_flags(module)
        start_time = time.time()
        try:
            if request.use_exploit_wrapper and hasattr(module, "_exploit"):
                raw_result = module._exploit()
            else:
                raw_result = module.run()
            duration = time.time() - start_time
            raw_result = ModuleExecutor._apply_browser_auxiliary_auto_return(module, raw_result)
            normalized = ModuleExecutor._coerce_module_result(raw_result)

            if request.collect_metrics:
                ModuleExecutor._record_metrics(
                    framework,
                    module,
                    duration,
                    success=normalized.success,
                    error=normalized.error,
                )

            if ModuleExecutor.is_scanner(module):
                scan_error = bool(getattr(module, "_scan_error", False))
                if scan_error or normalized.error == "scan_error":
                    return ModuleExecutionResult(
                        success=False,
                        result=normalized,
                        command_success=False,
                        finding=normalized.finding,
                        evidence=normalized.evidence,
                        session_id=normalized.session_id,
                        error="scan_error",
                    )
                return ModuleExecutor._execution_from_module_result(
                    normalized,
                    command_success=True,
                    raw_result=normalized,
                )

            return ModuleExecutor._execution_from_module_result(
                normalized,
                raw_result=normalized,
            )
        except Exception as exc:
            duration = time.time() - start_time
            if request.collect_metrics:
                ModuleExecutor._record_metrics(
                    framework,
                    module,
                    duration,
                    success=False,
                    error=str(exc),
                )
            return ModuleExecutionResult(
                success=False,
                error=str(exc),
                command_success=False,
            )

    @staticmethod
    def _execute_via_kernel(
        framework: Any,
        module: Any,
        request: ModuleExecutionRequest,
    ) -> ModuleExecutionResult:
        module_path = getattr(module, "__module__", "unknown")
        module_id = f"{module_path}_{int(time.time() * 1000)}"

        framework.event_bus.publish(
            EventType.MODULE_EXECUTING,
            {"module_path": module_path, "module_id": module_id},
            source="framework",
        )

        context = framework.runtime_kernel.execute_module(
            module_path=module_path,
            module_instance=module,
            module_id=module_id,
            sandbox_config=None,
            resource_limits=None,
            timeout=None,
            skip_preflight=True,
        )

        if context.execution_thread:
            context.execution_thread.join(timeout=300)

        if context.status == "completed":
            framework.event_bus.publish(
                EventType.MODULE_EXECUTED,
                {
                    "module_path": module_path,
                    "module_id": module_id,
                    "result": context.result,
                },
                source="framework",
            )
            if context.result is not None:
                normalized = ModuleExecutor._coerce_module_result(context.result)
                success = normalized.success
            else:
                normalized = ModuleResult(success=True)
                success = True
            return ModuleExecutor._execution_from_module_result(
                normalized,
                command_success=success,
                raw_result=context.result,
            )

        framework.event_bus.publish(
            EventType.MODULE_FAILED,
            {
                "module_path": module_path,
                "module_id": module_id,
                "error": context.error,
            },
            source="framework",
        )
        return ModuleExecutionResult(
            success=False,
            error=context.error,
            command_success=False,
        )

    @staticmethod
    def execute(framework: Any, request: ModuleExecutionRequest) -> ModuleExecutionResult:
        module = request.module
        module_name = getattr(module, "name", "unknown")
        observability = getattr(framework, "observability", None)
        track = (
            observability.track_module(module_name, framework=framework)
            if observability and observability.enabled
            else nullcontext()
        )
        with track:
            preflight = ModuleExecutor.run_preflight(
                framework,
                module,
                skip_scope_confirm=request.skip_scope_confirm,
                verbose_guardian_debug=request.verbose_guardian_debug,
            )
            if not preflight.allowed:
                return ModuleExecutionResult(
                    success=False,
                    blocked=True,
                    block_reason=preflight.block_reason,
                    missing_options=preflight.missing_options,
                    error=preflight.message,
                    command_success=False,
                )

            if request.use_runtime_kernel:
                result = ModuleExecutor._execute_via_kernel(framework, module, request)
            elif ModuleExecutor.is_payload(module):
                result = ModuleExecutor._execute_payload(module)
            elif ModuleExecutor.is_listener(module):
                result = ModuleExecutor._execute_listener(module, framework, request)
            else:
                result = ModuleExecutor._execute_regular(module, framework, request)

            if result.session_id and observability and observability.enabled:
                from core.observability.context import bind_session

                bind_session(result.session_id)
            return attach_schema_evidence(result, module=module, framework=framework)
