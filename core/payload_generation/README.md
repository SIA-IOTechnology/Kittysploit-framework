# Payload `generate()` contract

KittySploit payload modules should return one of the following from `generate()`:

## Preferred

`GeneratedArtifact` from `core.payload_generation` (schema version `1.0`).

```python
from core.payload_generation import GeneratedArtifact

def generate(self):
    source = "..."
    return GeneratedArtifact(
        content=source.encode("utf-8"),
        display_content=source.encode("utf-8"),
        content_type="text/plain",
        artifacts={"source": "/safe/path/shell.zig"},
        warnings=[],
    )
```

## Supported legacy returns

| Return type | Output behavior |
|-------------|-----------------|
| `bytes` / `bytearray` | Used directly in Output |
| `str` | Encoded as UTF-8 |
| `dict` with `content` | Uses `content` field |
| `dict` with artifact paths | Reads binary/source files; paths stay in `artifacts` |
| `Path` | Reads file bytes when present |
| `tuple` | First element is normalized |

## Invalid

- `None`
- Empty tuple
- Unsupported types (`list`, custom objects, …)

## Compilation workflows

When a module writes files to disk:

1. Put filesystem paths in `artifacts` (or dict keys ending with `_path`).
2. Put user-visible payload bytes in `content` / `display_content`.
3. Keep `output_dir` inside the workspace (`output/`).

## KittyForge integration

- KittyForge normalizes all returns through `normalize_payload_result()`.
- Legacy types are accepted with a deprecation warning and telemetry.
- Each build is registered under `output/kittyforge/builds/<build_id>/`.
