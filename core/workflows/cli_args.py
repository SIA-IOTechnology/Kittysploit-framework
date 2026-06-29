#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CLI argument normalization for workflow commands."""

from __future__ import annotations

from typing import List

from core.workflows.loader import list_workflow_ids

# argparse flags for ``workflows run``; any other ``--name`` becomes ``--set name=value``.
_RUN_KNOWN_FLAGS = frozenset({
    "file", "f", "target", "t", "set", "s", "dry-run", "from-workspace", "json", "help", "h",
})


def expand_workflow_variable_flags(args: List[str]) -> List[str]:
    """
    Map ``workflows run … --persona_name Jane Doe`` to ``--set persona_name=Jane Doe``.

    Keeps native flags (--target, --set, --dry-run, …) unchanged.
    """
    if not args:
        return args

    expanded = list(args)
    if expanded[0] in list_workflow_ids():
        expanded = ["run"] + expanded
    if not expanded or expanded[0] != "run":
        return args

    out: List[str] = ["run"]
    i = 1
    while i < len(expanded):
        token = expanded[i]
        if not token.startswith("-"):
            out.append(token)
            i += 1
            continue

        if token in ("-h", "--help"):
            out.append(token)
            i += 1
            continue

        opt = token[2:] if token.startswith("--") else token[1:]
        if "=" in opt:
            name, value = opt.split("=", 1)
            if name in _RUN_KNOWN_FLAGS:
                out.append(token)
            else:
                out.extend(["--set", f"{name}={value}"])
            i += 1
            continue

        if opt in _RUN_KNOWN_FLAGS:
            out.append(token)
            if opt in ("file", "f", "target", "t", "set", "s") and i + 1 < len(expanded):
                out.append(expanded[i + 1])
                i += 2
            else:
                i += 1
            continue

        if i + 1 < len(expanded) and not expanded[i + 1].startswith("-"):
            out.extend(["--set", f"{opt}={expanded[i + 1]}"])
            i += 2
        else:
            out.extend(["--set", f"{opt}="])
            i += 1

    return out
