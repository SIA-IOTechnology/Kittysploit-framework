# KittySploit JSON Schemas

This directory contains versioned JSON Schema contracts for cross-boundary data
shared by the framework, API, MCP server, reports, marketplace extensions, and
plugins.

Current schema set: `json/v1`

Instance contract version: `schema_version: "1.0"`

Entities:

- `Target`: normalized host, URL, service, asset, or scope item.
- `Evidence`: structured proof such as HTTP exchanges, command output,
  artifacts, screenshots, logs, proxy flows, or manual notes.
- `Finding`: actionable vulnerability or informational issue with linked
  targets, evidence, remediation, and retest state.
- `Job`: asynchronous module or framework execution state.
- `Session`: runtime or persisted interactive channel.
- `Report`: bundle of findings, targets, evidence, jobs, sessions, summary, and
  export metadata.
- `AgentAction`, `AgentObservation`, `AgentDecision`, `AgentState`, `AgentRun`:
  versioned autonomous workflow, checkpoint, replay, and audit contracts.
- `AgentBenchmarkResult`: comparable benchmark output with North Star metrics,
  outcome verdicts, per-run detail, and failure attribution for CI.

Python callers can use:

```python
from core.schemas import load_schema

finding_schema = load_schema("finding")
```
