"""Execute PDF generator callables for a callback host."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set

from lib.pdf.obfuscation import ensure_scheme, inject_credit, obfuscate_pdf, validate_url_or_ip

Generator = Callable[..., None]


def generator_slug(func: Callable) -> str:
    return getattr(func, "pdf_slug", func.__name__.replace("write_", "", 1))


def generator_host_mode(func: Callable) -> str:
    return getattr(func, "pdf_host_mode", _default_host_mode(func.__name__))


def generator_ext(func: Callable, slug: str) -> str:
    return getattr(func, "pdf_ext", ".svg" if slug == "imagemagick_svg_polyglot" else ".pdf")


def output_path(output_dir: Path, slug: str, ext: str = ".pdf") -> Path:
    return output_dir / f"pdf-{slug.replace('_', '-')}{ext}"


def validate_callback_host(host: str) -> bool:
    return validate_url_or_ip(host)


def _default_host_mode(name: str) -> str:
    if name == "write_eicar_polyglot":
        return "none"
    if name == "write_gotoe_unc":
        return "unc"
    if name.startswith("write_unc_") or name == "write_xfa_xslt_callback":
        return "host"
    return "scheme"


def _host_arg(mode: str, host: str) -> Optional[str]:
    if mode == "none":
        return None
    if mode == "unc":
        bare = host.replace("https://", "").replace("http://", "").split("/")[0]
        return f"\\\\{bare}\\test"
    if mode == "scheme":
        return ensure_scheme(host)
    return host


def _parse_filter(raw: str, available: Set[str]) -> Set[str]:
    raw = (raw or "").strip()
    if not raw or raw.lower() in ("all", "*"):
        return available
    selected: Set[str] = set()
    for part in raw.split(","):
        token = part.strip()
        if token in available:
            selected.add(token)
    return selected


def run_generators(
    host: str,
    output_dir: Path | str,
    generators: Iterable[Generator],
    *,
    tests: str = "all",
    obfuscate: int = 0,
    credit: bool = True,
) -> List[Path]:
    """Run module-declared generator callables."""
    if not validate_callback_host(host):
        raise ValueError(
            "Invalid callback URL or IP. Use a scheme (https://) or a valid IP address."
        )

    gens = list(generators)
    slug_by_func = {generator_slug(g): g for g in gens}
    selected = _parse_filter(tests, set(slug_by_func))

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    created: List[Path] = []

    for func in gens:
        slug = generator_slug(func)
        if slug not in selected:
            continue
        ext = generator_ext(func, slug)
        path = output_path(out, slug, ext)
        mode = generator_host_mode(func)
        arg = _host_arg(mode, host)
        if arg is None:
            func(path)
        else:
            func(path, arg)
        created.append(path)

    if credit:
        inject_credit(out)

    if obfuscate > 0:
        for filepath in created:
            if filepath.suffix == ".pdf":
                obfuscate_pdf(filepath, obfuscate)

    return created


def format_generator_slugs(generators: Iterable[Generator]) -> str:
    return ", ".join(generator_slug(g) for g in generators)
