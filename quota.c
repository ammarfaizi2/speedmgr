// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define USE_INTERNAL_SPEEDMGR_QUOTA
#include "quota.h"

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

static int create_unix_sock_server(const char *path)
{
	struct sockaddr_un addr;
	int fd, err;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	unlink(path);
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	err = listen(fd, 1);
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

int qo_init(struct spd_quota **sq_p, long long initial_quota, const char *unix_sock_path)
{
	struct spd_quota *sq;
	int ret;

	*sq_p = NULL;
	sq = calloc(1, sizeof(*sq));
	if (!sq)
		return -ENOMEM;

	if (initial_quota > 0) {
		sq->enabled = true;
		atomic_store_explicit(&sq->quota, initial_quota, memory_order_relaxed);
	}

	if (unix_sock_path) {
		ret = create_unix_sock_server(unix_sock_path);
		if (ret < 0) {
			free(sq);
			return ret;
		}

		sq->unix_fd = ret;
	} else {
		sq->unix_fd = -1;
	}

	ret = pthread_mutex_init(&sq->lock, NULL);
	if (ret < 0) {
		free(sq);
		return -ret;
	}

	*sq_p = sq;
	return 0;
}

void qo_free(struct spd_quota *sq)
{
	size_t i;

	if (!sq)
		return;

	if (sq->unix_fd >= 0)
		close(sq->unix_fd);

	for (i = 0; i < ARRAY_SIZE(sq->clients); i++) {
		if (sq->clients[i].fd >= 0)
			close(sq->clients[i].fd);
	}

	pthread_mutex_destroy(&sq->lock);
	free(sq);
}

bool qo_quota_exceeded(struct spd_quota *sq)
{
	if (!sq->enabled)
		return false;

	if (sq->exceeded)
		return true;

	if (atomic_load(&sq->quota) < 0) {
		sq->exceeded = true;
		return true;
	}

	return false;
}

void qo_quota_consume(struct spd_quota *sq, long long amount)
{
	long long cur;

	if (!sq->enabled)
		return;

	cur = atomic_fetch_sub(&sq->quota, amount) - amount;
	if (cur <= 0) {
		sq->exceeded = true;
		atomic_store(&sq->quota, 0ll);
	}
}

struct spd_quota_client *qo_quota_unix_accept(struct spd_quota *sq)
{
	struct spd_quota_client *c = NULL;
	size_t i;
	int fd;

	fd = accept4(sq->unix_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0)
		return NULL;

	pthread_mutex_lock(&sq->lock);
	for (i = 0; i < ARRAY_SIZE(sq->clients); i++) {
		c = &sq->clients[i];
		if (!c->is_used) {
			c->is_used = true;
			c->fd = fd;
			c->len = 0;
			goto out;
		}
	}

	close(fd);
	c = NULL;
out:
	pthread_mutex_unlock(&sq->lock);
	return c;
}

int qo_quota_unix_handle(struct spd_quota *sq, struct spd_quota_client *c)
{
	size_t len, expected_len;
	struct quota_pkt res;
	long long qf;
	uint8_t *buf;
	ssize_t ret;
	int err;

	len = sizeof(c->pkt) - c->len;
	buf = (uint8_t *)&c->pkt + c->len;
	ret = recv(c->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		err = -errno;
		if (err == -EINTR)
			err = -EAGAIN;

		return err;
	}

	if (!ret)
		return -ECONNRESET;

	c->len += (size_t)ret;

eval_pkt:
	expected_len = qo_get_pkt_expected_size(c->pkt.type);
	if (!expected_len)
		return -EINVAL;

	if (c->len < expected_len)
		return -EAGAIN;

	switch (c->pkt.type) {
	case QUOTA_PKT_CMD_ENABLE:
		sq->enabled = true;
		res.resp.before = atomic_load(&sq->quota);
		res.resp.after = res.resp.before;
		break;
	case QUOTA_PKT_CMD_DISABLE:
		sq->enabled = false;
		break;
	case QUOTA_PKT_CMD_SET:
		qf = atomic_exchange(&sq->quota, c->pkt.get);
		res.resp.before = qf;
		res.resp.after = c->pkt.get;
		break;
	case QUOTA_PKT_CMD_ADD:
		qf = atomic_fetch_add(&sq->quota, c->pkt.get);
		res.resp.before = qf;
		res.resp.after = qf + c->pkt.get;
		break;
	case QUOTA_PKT_CMD_SUB:
		qf = atomic_fetch_sub(&sq->quota, c->pkt.get);
		res.resp.before = qf;
		res.resp.after = qf - c->pkt.get;
		break;
	case QUOTA_PKT_CMD_GET:
		res.resp.before = atomic_load(&sq->quota);
		res.resp.after = res.resp.before;
		break;
	default:
		return -EINVAL;
	}

	res.exceeded = sq->exceeded;
	res.enabled = sq->enabled;
	res.type = QUOTA_PKT_RESP;
	memset(res.__pad, 0, sizeof(res.__pad));
	len = qo_get_pkt_expected_size(res.type);
	ret = send(c->fd, &res, len, MSG_DONTWAIT);
	if ((size_t)ret != len) {
		err = -errno;
		if (err == -EINTR || err == -EAGAIN)
			err = -ECONNRESET;

		return err;
	}

	c->len -= expected_len;
	if (c->len) {
		memmove(&c->pkt, (uint8_t *)&c->pkt + expected_len, c->len);
		goto eval_pkt;
	}

	return 0;
}

void qo_quota_unix_client_close(struct spd_quota *sq, struct spd_quota_client *c)
{
	close(c->fd);
	pthread_mutex_lock(&sq->lock);
	c->is_used = false;
	c->fd = -1;
	c->len = 0;
	pthread_mutex_unlock(&sq->lock);
}
