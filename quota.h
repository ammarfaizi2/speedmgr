// SPDX-License-Identifier: GPL-2.0-only
#ifndef SPEEDMGR__QUOTA_H
#define SPEEDMGR__QUOTA_H

#include <stdint.h>
#include <stddef.h>

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
		struct quota_pkt_ba	resp;
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
	default:
		return 1;
	}
}

#endif /* #ifndef SPEEDMGR__QUOTA_H */
