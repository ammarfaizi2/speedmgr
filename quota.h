// SPDX-License-Identifier: GPL-2.0-only
#ifndef SPEEDMGR__QUOTA_H
#define SPEEDMGR__QUOTA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

enum {
	QUOTA_PKT_CMD_ENABLE	= 1,
	QUOTA_PKT_CMD_DISABLE	= 2,
	QUOTA_PKT_CMD_SET	= 3,
	QUOTA_PKT_CMD_ADD	= 4,
	QUOTA_PKT_CMD_SUB	= 5,
	QUOTA_PKT_CMD_GET	= 6,
	QUOTA_PKT_RESP		= 7,
};

struct quota_pkt_ba {
	long long	before;
	long long	after;
} __packed;

struct quota_pkt {
	uint8_t		type;
	uint8_t		__pad[7];
	union {
		long long		add;
		long long		sub;
		long long		set;
		long long		get;
		struct {
			struct quota_pkt_ba	resp;
			bool			exceeded;
			bool			enabled;
		} __packed;
	};
} __packed;

static inline size_t qo_get_pkt_expected_size(uint8_t type)
{
	switch (type) {
	case QUOTA_PKT_CMD_ENABLE:
	case QUOTA_PKT_CMD_DISABLE:
		return 8 + sizeof(struct quota_pkt_ba);
	case QUOTA_PKT_CMD_SET:
	case QUOTA_PKT_CMD_ADD:
	case QUOTA_PKT_CMD_SUB:
		return 8 + sizeof(long long);
	case QUOTA_PKT_CMD_GET:
		return 1;
	case QUOTA_PKT_RESP:
		return 8 + sizeof(struct quota_pkt_ba) + 2;
	default:
		return 0;
	}
}

#ifdef USE_INTERNAL_SPEEDMGR_QUOTA

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#include <stdatomic.h>
#include <pthread.h>

struct spd_quota_client {
	bool			is_used;
	int			fd;
	size_t			len;
	struct quota_pkt	pkt;
};

struct spd_quota {
	volatile bool			enabled;
	volatile bool			exceeded;
	_Atomic(long long)		quota;
	int				unix_fd;
	struct spd_quota_client		clients[16];
	pthread_mutex_t			lock;
};

int qo_init(struct spd_quota **sq_p, long long initial_quota, const char *unix_sock_path);
bool qo_quota_exceeded(struct spd_quota *sq);
void qo_quota_consume(struct spd_quota *sq, long long amount);
struct spd_quota_client *qo_quota_unix_accept(struct spd_quota *sq);
int qo_quota_unix_handle(struct spd_quota *sq, struct spd_quota_client *c);
void qo_quota_unix_client_close(struct spd_quota *sq, struct spd_quota_client *c);
void qo_free(struct spd_quota *sq);

#endif /* #ifdef USE_INTERNAL_SPEEDMGR_QUOTA */

#endif /* #ifndef SPEEDMGR__QUOTA_H */
