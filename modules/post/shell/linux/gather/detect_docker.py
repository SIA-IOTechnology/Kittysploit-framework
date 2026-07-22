from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Docker / Container Detection",
        "description": (
            "Detect whether the session runs inside Docker, Podman, LXC, or Kubernetes "
            "(/.dockerenv, cgroups, mountinfo, systemd-detect-virt -c). "
            "Unlike detect_vm, this does not rely on hypervisor/DMI signals."
        ),
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["linux", "post", "gather", "docker", "container"],
        "agent": {
            "risk": "passive",
            "effects": [],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "cost": 0.5,
            "noise": 0.1,
            "value": 1.2,
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
                "suggested_followups": [
                    "post/shell/linux/gather/container_escape_check",
                    "post/shell/linux/exploits/copy_fail_docker_escape_cve_2026_31431",
                    "post/shell/multi/gather/privesc_suggester",
                ],
            },
        },
    }

    verbose = OptBool(False, "Print raw probe output for each check", False)

    def _run(self, command: str) -> str:
        try:
            output = self.linux_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def run(self):
        if not self.linux_require_linux():
            return False

        print_status("Detecting container / Docker environment...")
        evidence = []
        runtime = None

        # Marker files — strongest Docker/Podman signals
        print_status("Checking container marker files...")
        dockerenv = self._run("test -f /.dockerenv && echo yes || echo no")
        if dockerenv == "yes":
            evidence.append(("high", "Marker file /.dockerenv present"))
            runtime = runtime or "Docker"
            print_success("Found /.dockerenv")
        elif self.verbose:
            print_info("  /.dockerenv not present")

        containerenv = self._run("test -f /run/.containerenv && echo yes || echo no")
        if containerenv == "yes":
            evidence.append(("high", "Marker file /run/.containerenv present (Podman)"))
            runtime = runtime or "Podman"
            print_success("Found /run/.containerenv (Podman)")
        elif self.verbose:
            print_info("  /run/.containerenv not present")

        # cgroups — works on older Docker (v1) and many k8s setups
        print_status("Checking cgroups...")
        cgroup = self._run(
            "cat /proc/1/cgroup 2>/dev/null; echo ---; cat /proc/self/cgroup 2>/dev/null"
        )
        if self.verbose and cgroup:
            for line in cgroup.splitlines()[:20]:
                print_info(f"  {line}")
        runtime_from_cgroup = self._classify_cgroup(cgroup)
        if runtime_from_cgroup:
            evidence.append(("high", f"Cgroup path indicates {runtime_from_cgroup}"))
            runtime = runtime or runtime_from_cgroup
            print_success(f"Cgroup indicates {runtime_from_cgroup}")

        # systemd-detect-virt -c (container mode; detect_vm uses VM mode only)
        print_status("Checking systemd-detect-virt -c...")
        virt = self._run(
            "command -v systemd-detect-virt >/dev/null 2>&1 && "
            "systemd-detect-virt -c 2>/dev/null || echo unavailable"
        ).lower()
        if virt and virt not in ("unavailable", "none", ""):
            label = self._virt_label(virt)
            evidence.append(("high", f"systemd-detect-virt -c => {virt}"))
            runtime = runtime or label
            print_success(f"systemd-detect-virt -c: {virt}")
        elif self.verbose:
            print_info(f"  systemd-detect-virt -c: {virt or 'n/a'}")

        # Mount / filesystem signals
        print_status("Checking mountinfo / overlay...")
        mounts = self._run(
            "grep -E 'docker|overlay|containerd|kubelet|lxc|podman' "
            "/proc/self/mountinfo 2>/dev/null | head -n 15"
        )
        if mounts:
            evidence.append(("medium", "Container-related mounts in /proc/self/mountinfo"))
            runtime = runtime or self._runtime_from_mounts(mounts)
            print_success("Container-related mounts detected")
            if self.verbose:
                for line in mounts.splitlines()[:10]:
                    print_info(f"  {line}")
        elif self.verbose:
            print_info("  No docker/overlay/containerd mounts matched")

        # PID 1 often differs from host init inside containers
        print_status("Checking PID 1...")
        pid1 = self._run(
            "tr '\\0' ' ' < /proc/1/cmdline 2>/dev/null; "
            "echo; ls -l /proc/1/exe 2>/dev/null"
        )
        if self._pid1_looks_container(pid1):
            evidence.append(("medium", f"PID 1 looks containerized: {pid1.splitlines()[0][:80]}"))
            runtime = runtime or "container"
            print_success("PID 1 does not look like host init")
            if self.verbose and pid1:
                for line in pid1.splitlines()[:5]:
                    print_info(f"  {line}")
        elif self.verbose:
            print_info(f"  PID 1: {(pid1.splitlines() or ['n/a'])[0][:80]}")

        # Env / hostname soft signals
        print_status("Checking env / hostname hints...")
        soft = self._run(
            "hostname 2>/dev/null; "
            "printenv 2>/dev/null | grep -Ei "
            "'^(DOCKER_|KUBERNETES_|K8S_|container=|HOSTNAME=)' | head -n 20"
        )
        soft_hits = self._soft_env_hits(soft)
        for hit in soft_hits:
            evidence.append(("low", hit))
            print_info(f"  Hint: {hit}")
            if "kubernetes" in hit.lower() or "k8s" in hit.lower():
                runtime = runtime or "Kubernetes"
            elif "docker" in hit.lower():
                runtime = runtime or "Docker"

        # Summary
        print_status("=" * 60)
        if evidence:
            confidence = self._confidence(evidence)
            kind = (runtime or "container").upper()
            print_success(f"Container detected: {kind} (confidence={confidence})")
            print_info(f"Evidence ({len(evidence)}):")
            for severity, msg in evidence:
                print_info(f"  [{severity}] {msg}")
            print_info(
                "Suggested follow-up: post/shell/linux/gather/container_escape_check"
            )
        else:
            print_success("No container indicators found — likely bare metal or VM host")
            print_info(
                "Note: detect_vm checks hypervisors; a Docker guest on bare metal "
                "will often look like bare metal to detect_vm."
            )

        return True

    @staticmethod
    def _classify_cgroup(cgroup: str) -> str:
        text = (cgroup or "").lower()
        if not text:
            return ""
        if "kubepods" in text or "kubelet" in text:
            return "Kubernetes"
        if "/docker/" in text or "docker-" in text or ".scope" in text and "docker" in text:
            return "Docker"
        if "containerd" in text or "cri-containerd" in text:
            return "containerd"
        if "podman" in text or "libpod" in text:
            return "Podman"
        if "/lxc/" in text or "lxc.payload" in text:
            return "LXC"
        # Generic container path: .../docker-ce/... or long hex id under system.slice
        if "docker" in text:
            return "Docker"
        return ""

    @staticmethod
    def _virt_label(virt: str) -> str:
        mapping = {
            "docker": "Docker",
            "podman": "Podman",
            "lxc": "LXC",
            "lxc-libvirt": "LXC",
            "systemd-nspawn": "systemd-nspawn",
            "rkt": "rkt",
            "container-other": "container",
            "wsl": "WSL",
        }
        return mapping.get(virt, virt)

    @staticmethod
    def _runtime_from_mounts(mounts: str) -> str:
        text = (mounts or "").lower()
        if "kubelet" in text or "pods/" in text:
            return "Kubernetes"
        if "containerd" in text:
            return "containerd"
        if "podman" in text or "containers/storage" in text:
            return "Podman"
        if "docker" in text or "overlay" in text:
            return "Docker"
        return "container"

    @staticmethod
    def _pid1_looks_container(pid1: str) -> bool:
        text = (pid1 or "").lower()
        if not text.strip():
            return False
        host_like = (
            "/sbin/init",
            "/usr/lib/systemd/systemd",
            "/lib/systemd/systemd",
            "systemd",
        )
        # If exe clearly points at systemd/init as PID 1, not a strong container signal alone
        first = text.splitlines()[0] if text.splitlines() else text
        if any(h in first for h in ("systemd", "/sbin/init", "/bin/init")):
            return False
        container_like = (
            "docker-init",
            "tini",
            "dumb-init",
            "entrypoint",
            "/bin/sh",
            "/bin/bash",
            "sleep",
            "pause",
        )
        return any(c in text for c in container_like)

    @staticmethod
    def _soft_env_hits(blob: str) -> list:
        hits = []
        text = blob or ""
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("docker_") or "docker_" in low:
                hits.append(f"env: {line.strip()[:100]}")
            elif low.startswith("kubernetes_") or low.startswith("k8s_"):
                hits.append(f"env: {line.strip()[:100]}")
            elif low.startswith("container="):
                hits.append(f"env: {line.strip()[:100]}")
            elif low.startswith("hostname=") and len(line.split("=", 1)[-1].strip()) == 12:
                # Docker default hostname is often a 12-char container id
                hits.append(f"hostname looks like container id: {line.split('=', 1)[-1].strip()}")
        # bare hostname line (first line from hostname cmd)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if lines and "=" not in lines[0] and len(lines[0]) == 12 and lines[0].isalnum():
            hits.append(f"hostname looks like container id: {lines[0]}")
        # dedupe
        seen = set()
        out = []
        for h in hits:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out

    @staticmethod
    def _confidence(evidence: list) -> str:
        scores = {"high": 3, "medium": 2, "low": 1}
        total = sum(scores.get(sev, 0) for sev, _ in evidence)
        if total >= 5 or any(sev == "high" for sev, _ in evidence):
            return "high"
        if total >= 2:
            return "medium"
        return "low"
