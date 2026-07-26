#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from kittysploit import *
from core.utils.paths import data_dir
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin

SECTION_CHOICES = [
    "all",
    "procs",
    "arts",
    "mods",
    "avail",
    "progs",
    "links",
    "maps",
    "kprobes",
    "ftrace",
    "lsm",
    "perf",
]

MONITORING_PROG_HINTS = (
    "kprobe",
    "tracepoint",
    "raw_tracepoint",
    "perf_event",
    "lsm",
    "tracing",
    "fentry",
    "fexit",
)

REMEDIATION = [
    "kprobes (tracefs)        -> clear kprobe_events / ftrace",
    "BPF links (any type)     -> bpftool link detach / unload agent",
    "BPF maps (event buffers) -> agent unload or map wipe",
    "LKM ftrace hooks         -> unload kernel module",
    "perf-attached BPF progs  -> kill owner process or unload LKM",
    "auditd                   -> systemctl stop auditd (noisy)",
    "EDR process              -> freeze/cgroup (noisy) or avoid",
    "EDR kernel module        -> rmmod / unload (often blocked)",
]


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux EDR / eBPF Recon",
        "description": (
            "Fingerprint common Linux EDR/XDR agents via processes, filesystem "
            "artifacts, kernel modules, tracefs, LSM stack, and BPF objects "
            "(via bpftool when available). Scores vendors by indicator weight."
        ),
        "platform": Platform.LINUX,
        "author": ["KittySploit Team"],
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1518/001/",
            "https://man7.org/linux/man-pages/man8/bpftool.8.html",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["discovery"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "evidence"],
            "cost": 1.2,
            "noise": 0.25,
            "value": 1.4,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": ["shell"],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "edr_fingerprint", "from_detail": "vendor"}],
                "consumes_capabilities": [{"capability": "shell", "from_detail": ""}],
                "option_bindings": {},
                "suggested_followups": ["post/shell/linux/gather/enum_protections"],
            },
        },
    }

    sections = OptString("all","Comma-separated sections: " + ", ".join(SECTION_CHOICES),required=False)
    save_loot = OptBool(True, "Save JSON report under output/loot", required=False)
    verbose = OptBool(False, "Print full raw bpftool/tracefs dumps", required=False)

    def check(self):
        return self.linux_require_linux()

    def run(self):
        if not self.check():
            return False

        profiles = self._load_profiles()
        if not profiles:
            return False

        scores = {p["vendor"]: 0 for p in profiles}
        selected = self._parse_sections()
        report: Dict[str, Any] = {
            "sections": sorted(selected),
            "findings": {},
            "scores": {},
            "bpftool": self.linux_command_exists("bpftool"),
        }

        print_status(
            f"EDR recon — {len(profiles)} vendors, sections={','.join(sorted(selected))}"
        )
        if not report["bpftool"]:
            print_warning(
                "bpftool not found — BPF prog/link/map sections will be limited"
            )

        runners = {
            "procs": self._recon_processes,
            "arts": self._recon_artifacts,
            "mods": self._recon_modules,
            "avail": self._recon_available_funcs,
            "progs": self._recon_bpf_progs,
            "links": self._recon_bpf_links,
            "maps": self._recon_bpf_maps,
            "kprobes": self._recon_kprobes,
            "ftrace": self._recon_ftrace,
            "lsm": self._recon_lsm,
            "perf": self._recon_perf_bpf,
        }

        for name in SECTION_CHOICES[1:]:
            if name not in selected:
                continue
            print_info(f"\n=== {name} ===")
            try:
                report["findings"][name] = runners[name](profiles, scores)
            except Exception as exc:
                print_warning(f"{name} failed: {exc}")
                report["findings"][name] = {"error": str(exc)}

        report["scores"] = self._print_summary(scores)
        report["remediation"] = REMEDIATION

        if bool(self.save_loot):
            self._save_loot(report)
        return True


    def _load_profiles(self) -> List[Dict[str, Any]]:
        path = data_dir() / "helpers" / "linux" / "edr_profiles.json"
        if not path.is_file():
            print_error(f"EDR profiles missing: {path}")
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print_error(f"Invalid EDR profiles JSON: {exc}")
            return []
        if not isinstance(data, list) or not data:
            print_error("EDR profiles JSON must be a non-empty list")
            return []
        return data

    def _parse_sections(self) -> Set[str]:
        raw = str(self.sections or "all").strip().lower()
        if not raw or raw == "all":
            return set(SECTION_CHOICES[1:])
        parts = {p.strip() for p in raw.replace(";", ",").split(",") if p.strip()}
        unknown = parts - set(SECTION_CHOICES)
        if unknown:
            print_warning(f"Unknown sections ignored: {', '.join(sorted(unknown))}")
        selected = parts & set(SECTION_CHOICES[1:])
        if not selected:
            print_warning("No valid sections; defaulting to all")
            return set(SECTION_CHOICES[1:])
        return selected

    def _score(self, scores: Dict[str, int], vendor: str, delta: int) -> None:
        if vendor in scores:
            scores[vendor] += delta

    def _match_pat(self, text: str, patterns: List[str]) -> bool:
        low = text.lower()
        return any(p.lower() in low for p in patterns if p)

    def _match_vendor_bpf(self, profiles: List[Dict[str, Any]], name: str) -> Optional[str]:
        for prof in profiles:
            if self._match_pat(name, prof.get("bpf_pats") or []):
                return prof["vendor"]
        return None

    def _match_vendor_module(self, profiles: List[Dict[str, Any]], name: str) -> Optional[str]:
        low = name.lower()
        for prof in profiles:
            for mod in prof.get("modules") or []:
                if mod.lower() in low:
                    return prof["vendor"]
        return None

    def _cmd(self, command: str, timeout: int = 30) -> str:
        return self.linux_execute(command, timeout=timeout) or ""

    def _first_readable(self, paths: List[str]) -> Tuple[str, str]:
        for path in paths:
            q = self.linux_shell_quote(path)
            out = self._cmd(f"test -r {q} && cat {q} 2>/dev/null")
            if out.strip():
                return path, out
        return "", ""

    # ------------------------------------------------------------------
    # Recon sections
    # ------------------------------------------------------------------

    def _recon_processes(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        # Compact one-shot: pid + comm for numeric pids
        raw = self._cmd(
            "for d in /proc/[0-9]*; do "
            "c=$(cat \"$d/comm\" 2>/dev/null) || continue; "
            "printf '%s %s\\n' \"${d##*/}\" \"$c\"; "
            "done 2>/dev/null"
        )
        hits = []
        for line in raw.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            pid, comm = parts[0], parts[1]
            for prof in profiles:
                for proc in prof.get("procs") or []:
                    if proc.lower() in comm.lower():
                        hits.append(
                            {"pid": pid, "comm": comm, "vendor": prof["vendor"]}
                        )
                        self._score(scores, prof["vendor"], 10)
                        print_success(
                            f"pid={pid:<6} comm={comm:<24} vendor={prof['vendor']}"
                        )
                        break
                else:
                    continue
                break

        if not hits:
            print_info("no known EDR processes found")
        return {"hits": hits}

    def _recon_artifacts(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        file_hits = []
        dev_hits = []

        # Batch existence checks to reduce round-trips
        paths: List[Tuple[str, str, int]] = []
        for prof in profiles:
            for path in prof.get("files") or []:
                paths.append((path, prof["vendor"], 5))
            for dev in prof.get("devs") or []:
                paths.append((f"/dev/{dev}", prof["vendor"], 8))

        if paths:
            script = " ; ".join(
                f'test -e {self.linux_shell_quote(p)} && echo EXISTS:{i}'
                for i, (p, _, _) in enumerate(paths)
            )
            out = self._cmd(script)
            present = set()
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("EXISTS:"):
                    try:
                        present.add(int(line.split(":", 1)[1]))
                    except ValueError:
                        pass

            for i, (path, vendor, weight) in enumerate(paths):
                if i not in present:
                    continue
                entry = {"path": path, "vendor": vendor}
                if path.startswith("/dev/"):
                    dev_hits.append(entry)
                else:
                    file_hits.append(entry)
                self._score(scores, vendor, weight)
                print_success(f"{path:<40} vendor={vendor}")

        if not file_hits and not dev_hits:
            print_info("no known EDR artifacts found")
        return {"files": file_hits, "devs": dev_hits}

    def _recon_modules(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        raw = self._cmd("cat /proc/modules 2>/dev/null")
        hits = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            name, refcnt = parts[0], parts[2]
            state = parts[3] if len(parts) > 3 else ""
            vendor = self._match_vendor_module(profiles, name)
            if not vendor:
                continue
            hits.append(
                {"name": name, "refcnt": refcnt, "state": state, "vendor": vendor}
            )
            self._score(scores, vendor, 10)
            print_success(
                f"{name:<32} refcnt={refcnt:<4} state={state:<12} vendor={vendor}"
            )
        if not hits:
            print_info("no known EDR modules loaded")
        return {"hits": hits}

    def _recon_available_funcs(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        source, raw = self._first_readable(
            [
                "/sys/kernel/tracing/available_filter_functions",
                "/sys/kernel/debug/tracing/available_filter_functions",
            ]
        )
        if not source:
            print_warning("available_filter_functions not accessible (often needs root)")
            return {"source": "", "hits": [], "summary": {}}

        print_info(f"source: {source}")
        vendor_hits: Dict[str, int] = {}
        shown: Dict[str, int] = {}
        sample = []

        mod_index = {
            (m.lower()): prof["vendor"]
            for prof in profiles
            for m in (prof.get("modules") or [])
        }

        for line in raw.splitlines():
            line = line.rstrip()
            m = re.search(r"\[([^\]]+)\]\s*$", line)
            if not m:
                continue
            modname = m.group(1)
            vendor = mod_index.get(modname.lower())
            if not vendor:
                continue
            vendor_hits[vendor] = vendor_hits.get(vendor, 0) + 1
            self._score(scores, vendor, 1)
            n = shown.get(vendor, 0)
            if n < 5:
                print_success(f"{line[:56]:<56} [{modname}] vendor={vendor}")
                sample.append({"line": line, "module": modname, "vendor": vendor})
            elif n == 5:
                print_info(f"... more {vendor} symbols from [{modname}]")
            shown[vendor] = n + 1

        if not vendor_hits:
            print_info("no known EDR module symbols found")
            print_info("note: BPF-only EDRs won't appear here — check progs")
        else:
            print_info("summary:")
            for vendor, count in sorted(vendor_hits.items(), key=lambda x: -x[1]):
                print_info(f"  {vendor:<44} {count} exported symbols")

        return {"source": source, "hits": sample, "summary": vendor_hits}

    def _recon_bpf_progs(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        if not self.linux_command_exists("bpftool"):
            print_warning("bpftool missing — skip BPF programs")
            return {"available": False, "hits": []}

        raw = self._cmd("bpftool -j prog show 2>/dev/null || bpftool prog show 2>/dev/null")
        hits = []
        monitoring = 0
        edr_match = 0

        parsed = self._parse_bpftool_prog(raw)
        if parsed:
            print_info(f"{'id':<6} {'name':<36} {'type':<22} jit")
            print_info("-" * 70)
            for item in parsed:
                name = item.get("name") or ""
                ptype = str(item.get("type") or "")
                mon = any(h in ptype.lower() for h in MONITORING_PROG_HINTS)
                vendor = self._match_vendor_bpf(profiles, name) if name else None
                if mon:
                    monitoring += 1
                if vendor:
                    edr_match += 1
                    self._score(scores, vendor, 3)
                tags = []
                if mon:
                    tags.append("[monitoring]")
                if vendor:
                    tags.append(f"[!EDR! {vendor}]")
                jit = item.get("jited_prog_len") or item.get("bytes_xlated") or ""
                line = (
                    f"{str(item.get('id', '')):<6} {name:<36} {ptype:<22} "
                    f"jit={jit} {' '.join(tags)}"
                )
                if vendor or (bool(self.verbose) and mon):
                    print_success(line)
                elif bool(self.verbose):
                    print_info(line)
                hits.append({**item, "monitoring": mon, "vendor": vendor})
        else:
            # Fallback: show raw text and pattern-match names
            if bool(self.verbose) and raw.strip():
                print_info(raw[:4000])
            for line in raw.splitlines():
                vendor = self._match_vendor_bpf(profiles, line)
                if vendor:
                    edr_match += 1
                    self._score(scores, vendor, 3)
                    print_success(f"{line.strip()}  [!EDR! {vendor}]")
                    hits.append({"raw": line.strip(), "vendor": vendor})

        total = len(hits) if parsed else len([ln for ln in raw.splitlines() if ln.strip()])
        print_info(
            f"total≈{total}  monitoring_type={monitoring}  edr_pattern={edr_match}"
        )
        return {
            "available": True,
            "hits": hits,
            "monitoring": monitoring,
            "edr_match": edr_match,
            "raw": raw if bool(self.verbose) else "",
        }

    def _parse_bpftool_prog(self, raw: str) -> List[Dict[str, Any]]:
        raw = raw.strip()
        if not raw.startswith("[") and not raw.startswith("{"):
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            # sometimes a single object or id-keyed map
            if "id" in data:
                return [data]
            return [
                {"id": k, **v} if isinstance(v, dict) else {"id": k, "name": str(v)}
                for k, v in data.items()
            ]
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []

    def _recon_bpf_links(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        del profiles, scores  # links rarely carry EDR names
        if not self.linux_command_exists("bpftool"):
            print_warning("bpftool missing — skip BPF links")
            return {"available": False, "hits": []}

        raw = self._cmd("bpftool -j link show 2>/dev/null || bpftool link show 2>/dev/null")
        hits = self._parse_bpftool_prog(raw)
        if hits:
            print_info(f"{'link_id':<8} {'prog_id':<8} type")
            print_info("-" * 40)
            for item in hits:
                print_info(
                    f"{str(item.get('id', '')):<8} "
                    f"{str(item.get('prog_id', '')):<8} "
                    f"{item.get('type', '?')}"
                )
        elif raw.strip():
            if bool(self.verbose):
                print_info(raw[:3000])
            else:
                print_info(f"{len(raw.splitlines())} link lines (set VERBOSE true for dump)")
        else:
            print_info("no BPF links listed")
        print_info(f"total={len(hits) if hits else len([l for l in raw.splitlines() if l.strip()])}")
        return {"available": True, "hits": hits, "raw": raw if bool(self.verbose) else ""}

    def _recon_bpf_maps(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        if not self.linux_command_exists("bpftool"):
            print_warning("bpftool missing — skip BPF maps")
            return {"available": False, "hits": []}

        raw = self._cmd("bpftool -j map show 2>/dev/null || bpftool map show 2>/dev/null")
        interesting_types = {
            "perf_event_array",
            "ringbuf",
            "hash",
            "percpu_array",
            "percpu_hash",
            "lru_hash",
        }
        hits = []
        parsed = self._parse_bpftool_prog(raw)
        if parsed:
            print_info(f"{'id':<6} {'name':<36} {'type':<20} max_entries")
            print_info("-" * 70)
            for item in parsed:
                mtype = str(item.get("type") or "")
                max_e = int(item.get("max_entries") or 0)
                name = item.get("name") or ""
                if mtype not in interesting_types or max_e < 16:
                    continue
                vendor = self._match_vendor_bpf(profiles, name) if name else None
                if vendor:
                    self._score(scores, vendor, 2)
                tag = f"  [!EDR! {vendor}]" if vendor else ""
                line = f"{str(item.get('id', '')):<6} {name:<36} {mtype:<20} {max_e}{tag}"
                if vendor:
                    print_success(line)
                elif bool(self.verbose):
                    print_info(line)
                hits.append({**item, "vendor": vendor})
        else:
            for line in raw.splitlines():
                vendor = self._match_vendor_bpf(profiles, line)
                if vendor:
                    self._score(scores, vendor, 2)
                    print_success(f"{line.strip()}  [!EDR! {vendor}]")
                    hits.append({"raw": line.strip(), "vendor": vendor})

        if not hits:
            print_info("no monitoring-relevant BPF maps matched filters")
        return {"available": True, "hits": hits}

    def _recon_kprobes(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        source, raw = self._first_readable(
            [
                "/sys/kernel/tracing/kprobe_events",
                "/sys/kernel/debug/tracing/kprobe_events",
            ]
        )
        if not source:
            print_warning("tracefs kprobe_events not accessible")
            return {"source": "", "hits": []}

        print_info(f"source: {source}")
        hits = []
        edr_count = 0
        for line in raw.splitlines():
            line = line.rstrip()
            if not line:
                continue
            vendor = None
            for prof in profiles:
                pats = list(prof.get("bpf_pats") or []) + list(prof.get("modules") or [])
                if self._match_pat(line, pats):
                    vendor = prof["vendor"]
                    self._score(scores, vendor, 2)
                    break
            if vendor:
                edr_count += 1
                print_success(f"[!EDR!] {line}")
            elif bool(self.verbose):
                print_info(line)
            hits.append({"line": line, "vendor": vendor})

        total = len(hits)
        if not bool(self.verbose) and total and edr_count == 0:
            print_info(f"{total} kprobe lines (no EDR pattern; set VERBOSE true)")
        print_info(f"total={total}  edr_pattern={edr_count}")
        return {"source": source, "hits": hits, "edr_count": edr_count}

    def _recon_ftrace(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        del profiles, scores
        source, raw = self._first_readable(
            [
                "/sys/kernel/tracing/enabled_functions",
                "/sys/kernel/debug/tracing/enabled_functions",
            ]
        )
        if not source:
            print_warning("enabled_functions not accessible")
            print_info(
                "LKM ftrace hooks (register_ftrace_function) appear here "
                "and usually require unloading the module"
            )
            return {"source": "", "lines": 0}

        print_info(f"source: {source}")
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if bool(self.verbose):
            for ln in lines[:200]:
                print_info(ln)
            if len(lines) > 200:
                print_warning(f"... truncated ({len(lines)} total)")
        print_info(f"total={len(lines)}")
        return {"source": source, "lines": len(lines), "sample": lines[:50]}

    def _recon_lsm(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        del profiles, scores
        raw = self._cmd("cat /sys/kernel/security/lsm 2>/dev/null").strip()
        if raw:
            print_info(f"lsm stack: {raw}")
        else:
            print_warning("/sys/kernel/security/lsm not readable")
        print_info("BPF LSM programs are listed in the progs section when bpftool works")
        return {"lsm": raw}

    def _recon_perf_bpf(
        self, profiles: List[Dict[str, Any]], scores: Dict[str, int]
    ) -> Dict[str, Any]:
        del profiles, scores
        print_info("scanning /proc/*/fdinfo for prog_id entries...")
        lines: List[str] = []

        if self.linux_command_exists("python3"):
            raw = self._cmd(
                "python3 - <<'PY'\n"
                "import os\n"
                "hits=[]\n"
                "for pid in os.listdir('/proc'):\n"
                "    if not pid.isdigit():\n"
                "        continue\n"
                "    base=f'/proc/{pid}/fdinfo'\n"
                "    try:\n"
                "        fds=os.listdir(base)\n"
                "    except Exception:\n"
                "        continue\n"
                "    for fd in fds:\n"
                "        path=os.path.join(base, fd)\n"
                "        try:\n"
                "            with open(path) as f:\n"
                "                txt=f.read()\n"
                "        except Exception:\n"
                "            continue\n"
                "        for line in txt.splitlines():\n"
                "            if line.startswith('prog_id:'):\n"
                "                hits.append(f'pid={pid} fd={fd} {line}')\n"
                "                break\n"
                "        if len(hits) >= 200:\n"
                "            break\n"
                "    if len(hits) >= 200:\n"
                "        break\n"
                "print('\\n'.join(hits))\n"
                "PY",
                timeout=60,
            )
            lines = [ln.strip() for ln in raw.splitlines() if "prog_id:" in ln]

        if not lines:
            raw2 = self._cmd(
                "grep -R '^prog_id:' /proc/[0-9]*/fdinfo 2>/dev/null | head -n 200",
                timeout=60,
            )
            lines = [ln.strip() for ln in raw2.splitlines() if ln.strip()]

        for ln in lines[:50]:
            print_success(ln)
        if len(lines) > 50:
            print_warning(f"... {len(lines)} total (showing 50)")

        if not lines:
            print_info("none found (attachments may use modern BPF_LINK only)")
        else:
            print_warning(
                f"{len(lines)} perf-attached BPF prog refs — "
                "bpf_link_detach may not remove these"
            )
        return {"hits": lines}

    # ------------------------------------------------------------------
    # Summary / loot
    # ------------------------------------------------------------------

    def _print_summary(self, scores: Dict[str, int]) -> Dict[str, Any]:
        print_info("\n=== Detection Summary ===")
        print_info(f"{'vendor':<40} confidence")
        print_info("-" * 62)
        ranked = []
        for vendor, score in sorted(scores.items(), key=lambda x: -x[1]):
            if score <= 0:
                continue
            level = "HIGH" if score >= 20 else "MEDIUM" if score >= 10 else "LOW"
            ranked.append({"vendor": vendor, "score": score, "level": level})
            print_success(f"{vendor:<40} score={score:<4} {level}")
        if not ranked:
            print_info("no EDR indicators found")

        print_info("\n=== Remediation map ===")
        for line in REMEDIATION:
            print_info(f"  {line}")
        return {"ranked": ranked, "raw_scores": {k: v for k, v in scores.items() if v}}

    def _save_loot(self, report: Dict[str, Any]) -> None:
        host = (self._cmd("hostname 2>/dev/null") or "linux").strip()
        host = host.splitlines()[-1].strip() if host else "linux"
        safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host) or "linux"
        out_rel = os.path.join("loot", f"edr_recon_{safe_host}.json")
        if self.write_out_dir(out_rel, json.dumps(report, indent=2, default=str)):
            print_success(f"Saved EDR recon loot to output/{out_rel}")
        else:
            print_warning("Could not save loot")
