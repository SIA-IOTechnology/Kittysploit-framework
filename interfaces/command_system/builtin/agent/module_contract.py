#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Versioned on-disk module contracts for planner and executor gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.schemas import SCHEMA_VERSION
from interfaces.command_system.builtin.agent.agent_module_meta import normalize_agent_block
from interfaces.command_system.builtin.agent.metadata_linter import lint_agent_block_strict
from interfaces.command_system.builtin.agent.runtime_policy import action_is_non_idempotent, assess_module_risk

CONTRACT_VERSION = "1.0"
DEFAULT_SUCCESS_VALIDATORS = (
    "evidence_or_observation",
    "no_message_only_session",
)


@dataclass
class ModuleContract:
    module_path: str
    contract_version: str = CONTRACT_VERSION
    schema_version: str = SCHEMA_VERSION
    risk: str = ""
    effects: List[str] = field(default_factory=list)
    expected_requests: int = 1
    reversible: bool = True
    idempotent: bool = True
    approval_required: bool = False
    produces: List[str] = field(default_factory=list)
    prerequisites: Dict[str, Any] = field(default_factory=dict)
    incompatible_when: Dict[str, Any] = field(default_factory=dict)
    produces_capabilities: List[Dict[str, str]] = field(default_factory=list)
    consumes_capabilities: List[str] = field(default_factory=list)
    option_bindings: Dict[str, str] = field(default_factory=dict)
    options_schema: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    success_validators: List[str] = field(default_factory=lambda: list(DEFAULT_SUCCESS_VALIDATORS))
    network_destinations: List[str] = field(default_factory=list)
    privileges_required: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ModuleContract":
        data = dict(payload or {})
        return cls(
            module_path=str(data.get("module_path") or ""),
            contract_version=str(data.get("contract_version") or CONTRACT_VERSION),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            risk=str(data.get("risk") or ""),
            effects=[str(item) for item in (data.get("effects") or [])],
            expected_requests=int(data.get("expected_requests", 1) or 1),
            reversible=bool(data.get("reversible", True)),
            idempotent=bool(data.get("idempotent", True)),
            approval_required=bool(data.get("approval_required", False)),
            produces=[str(item) for item in (data.get("produces") or [])],
            prerequisites=dict(data.get("prerequisites") or {}),
            incompatible_when=dict(data.get("incompatible_when") or {}),
            produces_capabilities=[
                dict(row) for row in (data.get("produces_capabilities") or []) if isinstance(row, dict)
            ],
            consumes_capabilities=[str(item) for item in (data.get("consumes_capabilities") or [])],
            option_bindings=dict(data.get("option_bindings") or {}),
            options_schema={
                str(key): dict(value)
                for key, value in (data.get("options_schema") or {}).items()
                if isinstance(value, dict)
            },
            success_validators=[str(item) for item in (data.get("success_validators") or [])],
            network_destinations=[str(item) for item in (data.get("network_destinations") or [])],
            privileges_required=[str(item) for item in (data.get("privileges_required") or [])],
            side_effects=[str(item) for item in (data.get("side_effects") or [])],
        )


def build_module_contract(
    module_path: str,
    *,
    static_meta: Optional[Mapping[str, Any]] = None,
    agent_meta: Optional[Mapping[str, Any]] = None,
    options_schema: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Optional[ModuleContract]:
    """Build a contract from on-disk metadata without importing the module."""
    static = dict(static_meta or {})
    raw_agent = agent_meta if agent_meta is not None else static.get("agent")
    normalized = normalize_agent_block(raw_agent)
    if normalized is None:
        return None

    chain = normalized.get("chain") if isinstance(normalized.get("chain"), dict) else {}
    risk_level = str(normalized.get("risk") or "")
    risk = assess_module_risk({"agent": normalized, "path": module_path}, module_path)
    agent_block = raw_agent if isinstance(raw_agent, dict) else {}
    destinations = [
        str(item).strip().lower()
        for item in (agent_block.get("network_destinations") or agent_block.get("destinations") or [])
        if str(item).strip()
    ]
    privileges = [
        str(item).strip().lower()
        for item in (agent_block.get("privileges_required") or agent_block.get("privileges") or [])
        if str(item).strip()
    ]
    side_effects = [
        str(item).strip().lower()
        for item in (agent_block.get("side_effects") or [])
        if str(item).strip()
    ]
    validators = [
        str(item).strip()
        for item in (agent_block.get("success_validators") or DEFAULT_SUCCESS_VALIDATORS)
        if str(item).strip()
    ]

    return ModuleContract(
        module_path=str(module_path),
        risk=risk_level,
        effects=list(normalized.get("effects") or []),
        expected_requests=int(normalized.get("expected_requests", 1) or 1),
        reversible=bool(normalized.get("reversible", True)),
        idempotent=not action_is_non_idempotent(risk),
        approval_required=bool(normalized.get("approval_required", False)),
        produces=list(normalized.get("produces") or []),
        prerequisites=dict(normalized.get("requires") or {}),
        incompatible_when=dict(normalized.get("incompatible_when") or {}),
        produces_capabilities=[
            dict(row) for row in (chain.get("produces_capabilities") or []) if isinstance(row, dict)
        ],
        consumes_capabilities=[str(item) for item in (chain.get("consumes_capabilities") or [])],
        option_bindings=dict(chain.get("option_bindings") or {}),
        options_schema={
            str(key): dict(value)
            for key, value in (options_schema or {}).items()
            if isinstance(value, dict)
        },
        success_validators=validators or list(DEFAULT_SUCCESS_VALIDATORS),
        network_destinations=destinations,
        privileges_required=privileges,
        side_effects=side_effects,
    )


def validate_module_contract(contract: ModuleContract, *, strict: bool = False) -> List[str]:
    """Return contract issues; empty list means the contract is planner-ready."""
    issues: List[str] = []
    if not contract.module_path:
        issues.append("missing module_path")
    if contract.contract_version != CONTRACT_VERSION:
        issues.append(f"unsupported contract_version: {contract.contract_version}")

    agent_view = {
        "risk": contract.risk,
        "expected_requests": contract.expected_requests,
        "effects": contract.effects,
        "reversible": contract.reversible,
        "approval_required": contract.approval_required,
        "produces": contract.produces,
        "requires": contract.prerequisites,
        "incompatible_when": contract.incompatible_when,
        "chain": {
            "produces_capabilities": contract.produces_capabilities,
            "consumes_capabilities": contract.consumes_capabilities,
            "option_bindings": contract.option_bindings,
        },
    }
    if strict:
        issues.extend(lint_agent_block_strict(agent_view))
    else:
        from interfaces.command_system.builtin.agent.metadata_linter import lint_agent_block

        issues.extend(lint_agent_block(agent_view))

    if contract.options_schema:
        for name, spec in contract.options_schema.items():
            if not str(spec.get("description") or "").strip() and spec.get("required"):
                issues.append(f"required option {name!r} missing description in contract schema")
    return issues


def build_contract_from_static_validation(
    module_path: str,
    file_path: str,
    *,
    static_meta: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Combine static contract validation with agent contract normalization."""
    from core.utils.module_static_metadata import validate_static_module_contract

    validation = validate_static_module_contract(module_path, file_path)
    metadata = validation.get("metadata") if isinstance(validation.get("metadata"), dict) else {}
    options_schema = metadata.get("options") if isinstance(metadata.get("options"), dict) else {}
    contract = build_module_contract(
        module_path,
        static_meta=static_meta or metadata,
        options_schema=options_schema,
    )
    issues = list(validation.get("errors") or [])
    issues.extend(validation.get("warnings") or [])
    if contract is None:
        issues.append("missing agent metadata block")
        return {
            "module_path": module_path,
            "valid": False,
            "issues": issues,
            "contract": None,
            "static_validation": validation,
        }
    issues.extend(validate_module_contract(contract))
    return {
        "module_path": module_path,
        "valid": not issues,
        "issues": issues,
        "contract": contract.to_dict(),
        "static_validation": validation,
    }


def known_option_keys(contract: ModuleContract) -> set[str]:
    keys = set(contract.options_schema.keys())
    keys.update(contract.option_bindings.keys())
    return {str(key).strip().lower() for key in keys if str(key).strip()}
