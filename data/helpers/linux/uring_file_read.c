#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define QUEUE_DEPTH 8
#define CHUNK_SIZE  65536
#define MARK_START  "__KS_URING_START__"
#define MARK_END    "__KS_URING_END__"

struct uring {
	int ring_fd;
	void *sq_ptr;
	void *cq_ptr;
	struct io_uring_sqe *sqes;
	unsigned *sq_head;
	unsigned *sq_tail;
	unsigned *sq_mask;
	unsigned *sq_array;
	unsigned *cq_head;
	unsigned *cq_tail;
	unsigned *cq_mask;
	struct io_uring_cqe *cqes;
	size_t sq_ring_sz;
	size_t cq_ring_sz;
	unsigned sq_entries;
};

static int sys_io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	return (int)syscall(SYS_io_uring_setup, entries, p);
}

static int sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
			      unsigned flags)
{
	return (int)syscall(SYS_io_uring_enter, fd, to_submit, min_complete, flags,
			    NULL, 0);
}

static int uring_init(struct uring *u)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
	memset(u, 0, sizeof(*u));
	u->ring_fd = -1;

	u->ring_fd = sys_io_uring_setup(QUEUE_DEPTH, &p);
	if (u->ring_fd < 0)
		return -1;

	u->sq_entries = p.sq_entries;
	u->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	u->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

	u->sq_ptr = mmap(NULL, u->sq_ring_sz, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_POPULATE, u->ring_fd, IORING_OFF_SQ_RING);
	if (u->sq_ptr == MAP_FAILED)
		goto fail;

	u->cq_ptr = mmap(NULL, u->cq_ring_sz, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_POPULATE, u->ring_fd, IORING_OFF_CQ_RING);
	if (u->cq_ptr == MAP_FAILED)
		goto fail;

	u->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		       u->ring_fd, IORING_OFF_SQES);
	if (u->sqes == MAP_FAILED)
		goto fail;

	u->sq_head = (unsigned *)((char *)u->sq_ptr + p.sq_off.head);
	u->sq_tail = (unsigned *)((char *)u->sq_ptr + p.sq_off.tail);
	u->sq_mask = (unsigned *)((char *)u->sq_ptr + p.sq_off.ring_mask);
	u->sq_array = (unsigned *)((char *)u->sq_ptr + p.sq_off.array);

	u->cq_head = (unsigned *)((char *)u->cq_ptr + p.cq_off.head);
	u->cq_tail = (unsigned *)((char *)u->cq_ptr + p.cq_off.tail);
	u->cq_mask = (unsigned *)((char *)u->cq_ptr + p.cq_off.ring_mask);
	u->cqes = (struct io_uring_cqe *)((char *)u->cq_ptr + p.cq_off.cqes);
	return 0;

fail:
	if (u->sqes && u->sqes != MAP_FAILED)
		munmap(u->sqes, u->sq_entries * sizeof(struct io_uring_sqe));
	if (u->cq_ptr && u->cq_ptr != MAP_FAILED)
		munmap(u->cq_ptr, u->cq_ring_sz);
	if (u->sq_ptr && u->sq_ptr != MAP_FAILED)
		munmap(u->sq_ptr, u->sq_ring_sz);
	if (u->ring_fd >= 0)
		close(u->ring_fd);
	u->ring_fd = -1;
	return -1;
}

static void uring_free(struct uring *u)
{
	if (!u)
		return;
	if (u->sqes && u->sqes != MAP_FAILED)
		munmap(u->sqes, u->sq_entries * sizeof(struct io_uring_sqe));
	if (u->cq_ptr && u->cq_ptr != MAP_FAILED)
		munmap(u->cq_ptr, u->cq_ring_sz);
	if (u->sq_ptr && u->sq_ptr != MAP_FAILED)
		munmap(u->sq_ptr, u->sq_ring_sz);
	if (u->ring_fd >= 0)
		close(u->ring_fd);
	u->ring_fd = -1;
}

static struct io_uring_sqe *uring_get_sqe(struct uring *u)
{
	unsigned tail = *u->sq_tail;
	unsigned index = tail & *u->sq_mask;
	struct io_uring_sqe *sqe = &u->sqes[index];

	memset(sqe, 0, sizeof(*sqe));
	u->sq_array[index] = index;
	*u->sq_tail = tail + 1;
	return sqe;
}

static int uring_submit_wait(struct uring *u)
{
	return sys_io_uring_enter(u->ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
}

static int uring_peek_cqe(struct uring *u, struct io_uring_cqe *out)
{
	unsigned head = *u->cq_head;

	if (head == *u->cq_tail)
		return -1;
	*out = u->cqes[head & *u->cq_mask];
	*u->cq_head = head + 1;
	return 0;
}

static int uring_submit_one(struct uring *u, int *res)
{
	struct io_uring_cqe cqe;

	if (uring_submit_wait(u) < 0)
		return -1;
	if (uring_peek_cqe(u, &cqe) < 0)
		return -1;
	*res = (int)cqe.res;
	return 0;
}

static const char b64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct b64_state {
	unsigned char rem[3];
	int rem_len;
	int as_b64;
};

static void b64_encode_triplet(unsigned char a, unsigned char b, unsigned char c,
			       int n)
{
	unsigned char out[4];

	out[0] = (unsigned char)b64_table[a >> 2];
	out[1] = (unsigned char)b64_table[((a & 3) << 4) | (b >> 4)];
	out[2] = n > 1 ? (unsigned char)b64_table[((b & 15) << 2) | (c >> 6)] : '=';
	out[3] = n > 2 ? (unsigned char)b64_table[c & 63] : '=';
	(void)syscall(SYS_write, STDOUT_FILENO, out, 4);
}

static void emit_chunk(struct b64_state *st, const unsigned char *buf, size_t n)
{
	size_t i = 0;

	if (!st->as_b64) {
		(void)syscall(SYS_write, STDOUT_FILENO, buf, n);
		return;
	}

	while (st->rem_len && i < n) {
		st->rem[st->rem_len++] = buf[i++];
		if (st->rem_len == 3) {
			b64_encode_triplet(st->rem[0], st->rem[1], st->rem[2], 3);
			st->rem_len = 0;
		}
	}
	while (i + 3 <= n) {
		b64_encode_triplet(buf[i], buf[i + 1], buf[i + 2], 3);
		i += 3;
	}
	while (i < n)
		st->rem[st->rem_len++] = buf[i++];
}

static void emit_flush(struct b64_state *st)
{
	if (!st->as_b64 || st->rem_len == 0)
		return;
	if (st->rem_len == 1)
		b64_encode_triplet(st->rem[0], 0, 0, 1);
	else
		b64_encode_triplet(st->rem[0], st->rem[1], 0, 2);
	st->rem_len = 0;
}

static int read_via_syscall(const char *path, struct b64_state *st)
{
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
	unsigned char buf[CHUNK_SIZE];
	ssize_t n;

	if (fd < 0)
		return -errno;

	while ((n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf))) > 0)
		emit_chunk(st, buf, (size_t)n);
	syscall(SYS_close, fd);
	if (n < 0)
		return -errno;
	emit_flush(st);
	return 0;
}

static int read_via_uring(const char *path, struct b64_state *st)
{
	struct uring u;
	struct io_uring_sqe *sqe;
	struct iovec iov;
	unsigned char buf[CHUNK_SIZE];
	uint64_t offset = 0;
	int res;
	int fd;

	if (uring_init(&u) < 0)
		return -errno;

	sqe = uring_get_sqe(&u);
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (uint64_t)(uintptr_t)path;
	sqe->open_flags = O_RDONLY;
	sqe->len = 0;
	if (uring_submit_one(&u, &res) < 0 || res < 0) {
		int err = res < 0 ? -res : errno;
		uring_free(&u);
		return -err;
	}
	fd = res;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	for (;;) {
		sqe = uring_get_sqe(&u);
		sqe->opcode = IORING_OP_READV;
		sqe->fd = fd;
		sqe->addr = (uint64_t)(uintptr_t)&iov;
		sqe->len = 1;
		sqe->off = offset;
		if (uring_submit_one(&u, &res) < 0 || res < 0) {
			int err = res < 0 ? -res : errno;
			sqe = uring_get_sqe(&u);
			sqe->opcode = IORING_OP_CLOSE;
			sqe->fd = fd;
			uring_submit_one(&u, &res);
			uring_free(&u);
			return -err;
		}
		if (res == 0)
			break;
		emit_chunk(st, buf, (size_t)res);
		offset += (uint64_t)res;
	}

	sqe = uring_get_sqe(&u);
	sqe->opcode = IORING_OP_CLOSE;
	sqe->fd = fd;
	uring_submit_one(&u, &res);
	uring_free(&u);
	emit_flush(st);
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [--base64] [--syscall] <path>\n", argv0);
}

int main(int argc, char **argv)
{
	int as_b64 = 0;
	int force_syscall = 0;
	const char *path = NULL;
	int rc;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--base64"))
			as_b64 = 1;
		else if (!strcmp(argv[i], "--syscall"))
			force_syscall = 1;
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 1;
		} else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 1;
		} else {
			path = argv[i];
		}
	}
	if (!path) {
		usage(argv[0]);
		return 1;
	}

	struct b64_state st = { .as_b64 = as_b64 };

	dprintf(STDOUT_FILENO, "%s\n", MARK_START);

	if (force_syscall) {
		rc = read_via_syscall(path, &st);
	} else {
		rc = read_via_uring(path, &st);
		if (rc < 0) {
			memset(&st, 0, sizeof(st));
			st.as_b64 = as_b64;
			rc = read_via_syscall(path, &st);
		}
	}

	dprintf(STDOUT_FILENO, "\n%s\n", MARK_END);

	if (rc < 0) {
		fprintf(stderr, "read failed: %s\n", strerror(-rc));
		return 1;
	}
	return 0;
}
