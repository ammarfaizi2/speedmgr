// SPDX-License-Identifier: GPL-2.0-only

/*
 * For tproxy:
 *    sudo ./speedmgr -w 1 -b [::]:4444 -t [::]:0 -U 1M -I 1000 -D 1M -d 1000 -o 1111;
 *    sudo iptables -t nat -I OUTPUT -p tcp -j REDIRECT --to-ports 4444;
 *    sudo iptables -t nat -I OUTPUT -m mark --mark 1111 -j ACCEPT;
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif

#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#endif


/*
 * The number of `struct epoll_event` array members.
 */
#define NR_EPOLL_EVENTS 128

/*
 * The number of initial client slots.
 */
#define NR_INIT_CLIENT_ARR	2

#define NR_INIT_SPD_BUCKET_ARR	32

#define NR_INIT_RECV_BUF_BYTES	2048
#define NR_MAX_RECV_BUF_BYTES	4096

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <sys/eventfd.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "ht.h"

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#define g_dbg_level (1)
static volatile bool *g_stop;
static uint8_t g_verbose;

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#if 1
#define pr_debug(fmt, ...)	printf("[%08d] dbug: " fmt "\n", gettid(), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do { } while (0)
#endif

#define pr_error(fmt, ...)	printf("[%08d] perr: " fmt "\n", gettid(), ##__VA_ARGS__)
#define pr_info(fmt, ...)	printf("[%08d] info: " fmt "\n", gettid(), ##__VA_ARGS__)

#define pr_vl_dbg(level, fmt, ...)		\
do {						\
	if (g_dbg_level >= level)		\
		pr_debug(fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_errorv(fmt, ...)			\
do {						\
	if (g_verbose)				\
		pr_error(fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_infov(fmt, ...)			\
do {						\
	if (g_verbose)				\
		pr_info(fmt, ##__VA_ARGS__);	\
} while (0)

struct sockaddr_in46 {
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
};

struct spd_tkn {
	_Atomic(uint64_t)	tkn;
	_Atomic(uint64_t)	last_fill;
	uint64_t		fill_intv;
	uint64_t		max;
};

struct ip_spd_bucket {
	struct spd_tkn		up_tkn;
	struct spd_tkn		dn_tkn;
	_Atomic(uint16_t)	nr_conns;
};

struct ip_spd_map {
	ht_t			ht;
	size_t			cap;
	size_t			len;
	pthread_mutex_t		lock;
	struct ip_spd_bucket	**bucket_arr;
};

struct client_endp {
	int			fd;
	uint32_t		ep_mask;
	size_t			len;
	size_t			cap;
	char			*buf;
	struct sockaddr_in46	addr;
};

enum {
	RTF_UP_RATE_LIMITED	= (1u << 0u),
	RTF_DN_RATE_LIMITED	= (1u << 1u),
};

struct client_state {
	struct client_endp	client_ep;
	struct client_endp	target_ep;
	struct ip_spd_bucket	*spd;
	uint32_t		idx;
	uint8_t			rate_limit_flags;
	bool			target_connected;
	bool			is_used;
};

struct stack_u32 {
	pthread_mutex_t	lock;
	uint32_t	sp;
	uint32_t	bp;
	uint32_t	*data;
};

struct server_ctx;

struct server_wrk {
	int			ep_fd;
	int			ev_fd;
	int			timer_fd;
	int			ep_timeout;

	uint32_t		idx;
	uint32_t		client_arr_size;
	_Atomic(uint32_t)	nr_online_clients;
	uint64_t		next_timer_ns;

	pthread_t		thread;
	pthread_mutex_t		epass_mutex;	/* When passing a client to another worker */
	struct server_ctx	*ctx;
	struct client_state	**clients;
	struct stack_u32	cl_stack;

	bool			handle_events_should_stop;
	bool			timer_is_armed;
	struct epoll_event	events[NR_EPOLL_EVENTS];
};

/*
 * Server configuration.
 */
struct server_cfg {
	uint8_t			verbose;
	int			backlog;
	uint32_t		nr_workers;
	uint32_t		out_mark;
	uint64_t		up_limit;
	uint64_t		up_interval;
	uint64_t		down_limit;
	uint64_t		down_interval;
	struct sockaddr_in46	bind_addr;
	struct sockaddr_in46	target_addr;
};

/*
 * Server context.
 */
struct server_ctx {
	volatile bool		should_stop;
	bool			accept_stopped;
	bool			need_timer;
	int			tcp_fd;
	struct server_wrk	*workers;
	struct server_cfg	cfg;
	struct ip_spd_map	spd_map;
	pthread_mutex_t		accept_mutex;
};

enum {
	EPL_EV_EVENTFD		= (0x0001ull << 48ull),
	EPL_EV_TCP_ACCEPT	= (0x0002ull << 48ull),
	EPL_EV_TCP_CLIENT_DATA	= (0x0003ull << 48ull),
	EPL_EV_TCP_TARGET_DATA	= (0x0004ull << 48ull),
	EPL_EV_TCP_TARGET_CONN	= (0x0005ull << 48ull),
	EPL_EV_TIMERFD		= (0x0006ull << 48ull)
};

#define EPL_EV_MASK		(0xffffull << 48ull)
#define GET_EPL_EV(data)	((data) & EPL_EV_MASK)
#define GET_EPL_DT(data)	((void *)((data) & ~EPL_EV_MASK))

static const struct option long_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "workers",		required_argument,	NULL,	'w' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ "backlog",		required_argument,	NULL,	'B' },
	{ "up-limit",		required_argument,	NULL,	'U' },
	{ "up-interval",	required_argument,	NULL,	'I' },
	{ "down-limit",		required_argument,	NULL,	'D' },
	{ "down-interval",	required_argument,	NULL,	'd' },
	{ "out-mark",		required_argument,	NULL,	'o' },
	{ NULL,			0,			NULL,	0 },
};
static const char short_options[] = "hVw:b:t:vB:U:I:D:d:o:";

static void show_help(const void *app)
{
	printf("Usage: %s [OPTIONS]\n", (const char *)app);
	printf("Options:\n");
	printf("  -h, --help\t\t\tShow this help message\n");
	printf("  -V, --version\t\t\tShow version information\n");
	printf("  -w, --workers=NUM\t\tNumber of worker threads\n");
	printf("  -b, --bind=ADDR\t\tBind address, addr:port\n");
	printf("  -t, --target=ADDR\t\tTarget address, addr:port\n");
	printf("  -v, --verbose\t\t\tVerbose mode\n");
	printf("  -B, --backlog=NUM\t\tBacklog size\n");
	printf("  -U, --up-limit=NUM\t\tUpload speed limit (bytes)\n");
	printf("  -I, --up-interval=NUM\t\tUpload fill interval (seconds)\n");
	printf("  -D, --down-limit=NUM\t\tDownload speed limit (bytes)\n");
	printf("  -d, --down-interval=NUM\tDownload fill interval (seconds)\n");
	printf("  -o, --out-mark=NUM\t\tOutgoing connection packet mark\n");
}

static int parse_addr_and_port(const char *str, struct sockaddr_in46 *out)
{
	char *addr, *port;
	in_port_t *port_p;
	int ret;

	addr = strdup(str);
	if (!addr)
		return -ENOMEM;

	port = strchr(addr, ']');
	if (port)
		port++;
	else
		port = addr;

	port = strchr(port, ':');
	if (!port) {
		pr_error("Invalid address and port combination: \"%s\"", str);
		pr_error("Missing port number");
		ret = -EINVAL;
		goto out;
	}

	*port = '\0';
	port++;

	memset(out, 0, sizeof(*out));
	if (addr[0] == '[' && addr[strlen(addr) - 1] == ']') {
		addr[strlen(addr) - 1] = '\0';

		out->sa.sa_family = AF_INET6;
		ret = inet_pton(AF_INET6, addr + 1, &out->in6.sin6_addr);
		if (ret != 1) {
			pr_error("Invalid IPv6 address: %s", addr);
			ret = -EINVAL;
			goto out;
		}

		port_p = &out->in6.sin6_port;
	} else {
		out->sa.sa_family = AF_INET;
		ret = inet_pton(AF_INET, addr, &out->in4.sin_addr);
		if (ret != 1) {
			pr_error("Invalid IPv4 address: %s", addr);
			ret = -EINVAL;
			goto out;
		}

		port_p = &out->in4.sin_port;
	}

	ret = atoi(port);
	if (ret < 0 || ret > 65535) {
		pr_error("Invalid port in the address and port combination: \"%s\"", str);
		pr_error("Port must be between 0 and 65535");
		ret = -EINVAL;
		goto out;
	}

	*port_p = htons((uint16_t)ret);
	ret = 0;

out:
	free(addr);
	return ret;
}

static int parse_args(int argc, char *argv[], struct server_cfg *cfg)
{
	struct parse_state {
		bool got_bind_addr;
		bool got_target_addr;

		bool got_up_limit;
		bool got_up_interval;

		bool got_down_limit;
		bool got_down_interval;
	} p;

	cfg->backlog = 300;
	cfg->nr_workers = 4;
	cfg->verbose = 0;

	memset(&p, 0, sizeof(p));
	while (1) {
		int q, i;
		char *t;

		q = getopt_long(argc, argv, short_options, long_options, &i);
		if (q == -1)
			break;

		switch (q) {
		case 'h':
			show_help(argv[0]);
			return 1;
		case 'V':
			printf("speedmgr 0.1\n");
			return 1;
		case 'w':
			cfg->nr_workers = atoi(optarg);
			if (cfg->nr_workers <= 0) {
				pr_error("Invalid number of workers: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'b':
			if (parse_addr_and_port(optarg, &cfg->bind_addr)) {
				pr_error("Invalid bind address: %s", optarg);
				return -EINVAL;
			}

			p.got_bind_addr = true;
			break;
		case 't':
			if (parse_addr_and_port(optarg, &cfg->target_addr)) {
				pr_error("Invalid target address: %s", optarg);
				return -EINVAL;
			}

			p.got_target_addr = true;
			break;
		case 'v':
			cfg->verbose = 1;
			break;
		case 'B':
			cfg->backlog = atoi(optarg);
			if (cfg->backlog <= 0) {
				pr_error("Invalid backlog size: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'U':
			cfg->up_limit = strtoull(optarg, &t, 10);
			p.got_up_limit = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'K' || *t == 'k') {
				cfg->up_limit *= 1024;
			} else if (*t == 'M' || *t == 'm') {
				cfg->up_limit *= 1024 * 1024;
			} else if (*t == 'G' || *t == 'g') {
				cfg->up_limit *= 1024 * 1024 * 1024;
			} else if (*t != '\0') {
				pr_error("Invalid upload limit: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'I':
			cfg->up_interval = strtoull(optarg, &t, 10);
			p.got_up_interval = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'h') {
				cfg->up_interval *= 1000 * 3600;
			} else if (*t == 'm') {
				cfg->up_interval *= 1000 * 60;
			} else if (*t == 's') {
				cfg->up_interval *= 1000;
			} else {
				pr_error("Invalid upload interval: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'D':
			cfg->down_limit = strtoull(optarg, &t, 10);
			p.got_down_limit = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'K' || *t == 'k') {
				cfg->down_limit *= 1024;
			} else if (*t == 'M' || *t == 'm') {
				cfg->down_limit *= 1024 * 1024;
			} else if (*t == 'G' || *t == 'g') {
				cfg->down_limit *= 1024 * 1024 * 1024;
			} else if (*t != '\0') {
				pr_error("Invalid download limit: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'd':
			cfg->down_interval = strtoull(optarg, &t, 10);
			p.got_down_interval = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'h') {
				cfg->down_interval *= 1000 * 3600;
			} else if (*t == 'm') {
				cfg->down_interval *= 1000 * 60;
			} else if (*t == 's') {
				cfg->down_interval *= 1000;
			} else {
				pr_error("Invalid download interval: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'o':
			cfg->out_mark = strtoul(optarg, &t, 10);
			if (!t || *t != '\0') {
				pr_error("Invalid outgoing packet mark: %s", optarg);
				return -EINVAL;
			}
			break;
		case '?':
			return -EINVAL;
		default:
			break;
		}
	}

	if (!p.got_bind_addr) {
		pr_error("Missing bind address (the -b option)");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (!p.got_target_addr) {
		pr_error("Missing target address (the -t option)");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (p.got_up_limit ^ p.got_up_interval) {
		pr_error("Upload limit and upload interval must be specified together");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (p.got_down_limit ^ p.got_down_interval) {
		pr_error("Download limit and download interval must be specified together");
		show_help(argv[0]);
		return -EINVAL;
	}

	return 0;
}

static const char *sockaddr_to_str(struct sockaddr_in46 *addr)
{
	static __thread char _buf[8][INET6_ADDRSTRLEN + sizeof("[]:65535")];
	static __thread uint8_t _counter;
	char *buf = _buf[_counter++ % ARRAY_SIZE(_buf)];

	if (addr->sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &addr->in4.sin_addr, buf, INET_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), 
			 ":%hu", ntohs(addr->in4.sin_port));
		return buf;
	}


	if (IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		inet_ntop(AF_INET, &addr->in6.sin6_addr.s6_addr32[3], buf, INET_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), ":%hu",
			 ntohs(addr->in6.sin6_port));
	} else {
		*buf = '[';
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf + 1, INET6_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), "]:%hu",
			 ntohs(addr->in6.sin6_port));
	}

	return buf;
}

static int init_stack_u32(struct stack_u32 *stack, uint32_t size)
{
	uint32_t *arr;
	int ret;

	arr = malloc(size * sizeof(*arr));
	if (!arr)
		return -ENOMEM;

	ret = pthread_mutex_init(&stack->lock, NULL);
	if (ret) {
		free(arr);
		return -ret;
	}

	stack->data = arr;
	stack->sp = 0;
	stack->bp = size;
	return 0;
}

static void free_stack_u32(struct stack_u32 *stack)
{
	pr_vl_dbg(3, "free_stack_u32: stack=%p; stack_size=%u", stack, stack->bp);
	pthread_mutex_lock(&stack->lock);
	pthread_mutex_unlock(&stack->lock);
	pthread_mutex_destroy(&stack->lock);
	free(stack->data);
}

static int __upsize_stack_u32(struct stack_u32 *stack, uint32_t new_size)
{
	uint32_t *new_data;

	new_data = realloc(stack->data, new_size * sizeof(*new_data));
	if (!new_data)
		return -ENOMEM;

	stack->data = new_data;
	stack->bp = new_size;
	return 0;
}

static int __push_stack_u32(struct stack_u32 *stack, uint32_t data)
{
	if (stack->sp >= stack->bp)
		return -EAGAIN;

	stack->data[stack->sp++] = data;
	return 0;
}

static int __pop_stack_u32(struct stack_u32 *stack, uint32_t *data)
{
	if (stack->sp == 0)
		return -EAGAIN;

	*data = stack->data[--stack->sp];
	return 0;
}

static int push_stack_u32(struct stack_u32 *stack, uint32_t data)
{
	int ret;

	pthread_mutex_lock(&stack->lock);
	ret = __push_stack_u32(stack, data);
	pthread_mutex_unlock(&stack->lock);
	return ret;
}

static int pop_stack_u32(struct stack_u32 *stack, uint32_t *data)
{
	int ret;

	pthread_mutex_lock(&stack->lock);
	ret = __pop_stack_u32(stack, data);
	pthread_mutex_unlock(&stack->lock);
	return ret;
}

static int init_client_stack(struct server_wrk *w)
{
	uint32_t i;
	int ret;

	w->client_arr_size = NR_INIT_CLIENT_ARR;
	ret = init_stack_u32(&w->cl_stack, w->client_arr_size);
	if (ret) {
		pr_error("init_client_stack: Failed to initialize client stack: %s", strerror(-ret));
		return ret;
	}

	i = w->client_arr_size;
	while (i--) {
		ret = __push_stack_u32(&w->cl_stack, i);
		if (ret) {
			free_stack_u32(&w->cl_stack);
			pr_error("init_client_stack: Failed to push client index to stack: %s", strerror(-ret));
			return ret;
		}
	}

	return 0;
}

static void free_client_stack(struct server_wrk *w)
{
	free_stack_u32(&w->cl_stack);
}

static int try_increase_rlimit_nofile(void)
{
	struct rlimit rlim;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret) {
		ret = errno;
		pr_error("Failed to get RLIMIT_NOFILE: %s", strerror(ret));
		return -ret;
	}

	if (rlim.rlim_cur >= rlim.rlim_max)
		return 0;

	rlim.rlim_cur = rlim.rlim_max;
	ret = setrlimit(RLIMIT_NOFILE, &rlim);
	if (ret) {
		ret = errno;
		pr_error("Failed to set RLIMIT_NOFILE: %s", strerror(ret));
		return -ret;
	}

	return 0;
}

static void signal_handler(int sig)
{
	*g_stop = true;
	(void)sig;
}

static int install_signal_handlers(struct server_ctx *ctx)
{
	struct sigaction sa = { .sa_handler = signal_handler };
	int ret = 0;

	g_stop = &ctx->should_stop;
	ret |= sigaction(SIGINT, &sa, NULL);
	ret |= sigaction(SIGTERM, &sa, NULL);
	ret |= sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	ret |= sigaction(SIGPIPE, &sa, NULL);
	if (ret)
		goto out_err;

	return 0;

out_err:
	pr_error("Failed to install signal handlers: %s", strerror(errno));
	return ret;
}

static int init_spd_map(struct server_ctx *ctx)
{
	struct ip_spd_map *map = &ctx->spd_map;
	int ret;

	if (!ctx->need_timer)
		return 0;

	ret = ht_create(&map->ht);
	if (ret)
		return ret;

	map->len = 0;
	map->cap = NR_INIT_SPD_BUCKET_ARR;
	map->bucket_arr = calloc(map->cap, sizeof(*map->bucket_arr));
	if (!map->bucket_arr) {
		ht_destroy(&map->ht);
		return -ENOMEM;
	}

	ret = pthread_mutex_init(&map->lock, NULL);
	if (ret) {
		free(map->bucket_arr);
		ht_destroy(&map->ht);
		return -ret;
	}

	return 0;
}

static void free_spd_map(struct server_ctx *ctx)
{
	struct ip_spd_map *map = &ctx->spd_map;
	size_t i;

	if (!ctx->need_timer)
		return;

	if (!map->bucket_arr)
		return;

	for (i = 0; i < map->len; i++)
		free(map->bucket_arr[i]);

	free(map->bucket_arr);
	pthread_mutex_destroy(&map->lock);
	ht_destroy(&map->ht);
}

static int init_socket(struct server_ctx *ctx)
{
	int tcp_fd, ret, family;
	socklen_t len;

	ctx->accept_stopped = false;
	family = ctx->cfg.bind_addr.sa.sa_family;
	tcp_fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (tcp_fd < 0) {
		pr_error("Failed to create socket: %s", strerror(errno));
		return -errno;
	}

#ifdef SO_REUSEADDR
	ret = 1;
	setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
#endif

	if (family == AF_INET6)
		len = sizeof(ctx->cfg.bind_addr.in6);
	else
		len = sizeof(ctx->cfg.bind_addr.in4);

	ret = bind(tcp_fd, &ctx->cfg.bind_addr.sa, len);
	if (ret) {
		ret = -errno;
		pr_error("Failed to bind socket: %s", strerror(-ret));
		goto out;
	}

	ret = listen(tcp_fd, ctx->cfg.backlog);
	if (ret) {
		ret = -errno;
		pr_error("Failed to listen on socket: %s", strerror(-ret));
		goto out;
	}

	pr_info("Listening on %s...", sockaddr_to_str(&ctx->cfg.bind_addr));
	ctx->tcp_fd = tcp_fd;
	return 0;

out:
	close(tcp_fd);
	return ret;
}

static void free_socket(struct server_ctx *ctx)
{
	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);
}

static void init_client_ep(struct client_endp *ep)
{
	ep->fd = -1;
	ep->len = 0;
	ep->cap = 0;
	ep->buf = NULL;
	memset(&ep->addr, 0, sizeof(ep->addr));
}

static void init_client_state(struct client_state *c)
{
	init_client_ep(&c->client_ep);
	init_client_ep(&c->target_ep);
	c->spd = NULL;
	c->rate_limit_flags = 0;
	c->target_connected = false;
	c->is_used = false;
}

static struct client_state *alloc_client_state(void)
{
	struct client_state *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	init_client_state(c);
	return c;
}

static void reset_client_ep(struct client_endp *ep, bool preserve_buf,
			    size_t max_preserve)
{
	if (ep->fd >= 0) {
		close(ep->fd);
		ep->fd = -1;
	}

	if (ep->buf) {
		if (preserve_buf && ep->cap <= max_preserve) {
			ep->len = 0;
		} else {
			free(ep->buf);
			ep->buf = NULL;
			ep->len = 0;
			ep->cap = 0;
		}
	} else {
		ep->len = 0;
		ep->cap = 0;
	}

	memset(&ep->addr, 0, sizeof(ep->addr));
}

static void reset_client_state(struct client_state *c, bool preserve_buf,
			       size_t max_preserve)
{
	/*
	 * The caller must already put c->spd.
	 */
	assert(!c->spd);

	/*
	 * The caller must only pass a client state that is used.
	 */
	assert(c->is_used);

	reset_client_ep(&c->client_ep, preserve_buf, max_preserve);
	reset_client_ep(&c->target_ep, preserve_buf, max_preserve);

	c->spd = NULL;
	c->rate_limit_flags = 0;
	c->target_connected = false;
	c->is_used = false;
}

static int upsize_clients(struct server_wrk *w)
{
	struct client_state **new_arr;
	size_t old_len;
	size_t new_len;
	uint32_t i;
	int ret = 0;

	pthread_mutex_lock(&w->cl_stack.lock);
	old_len = w->client_arr_size;
	new_len = (old_len + 1) * 2;
	new_arr = realloc(w->clients, new_len * sizeof(*new_arr));
	if (!new_arr) {
		ret = -ENOMEM;
		goto out;
	}

	w->clients = new_arr;
	w->client_arr_size = new_len;
	ret = __upsize_stack_u32(&w->cl_stack, w->client_arr_size);
	if (ret)
		goto out;

	for (i = old_len; i < new_len; i++) {
		struct client_state *c = alloc_client_state();
		if (!c) {
			ret = -ENOMEM;
			goto out;
		}

		c->idx = i;
		w->clients[i] = c;

		ret = __push_stack_u32(&w->cl_stack, i);
		assert(!ret);
		(void)ret;
	}

	pr_infov("upsize_clients: old_size=%zu; new_size=%zu (thread=%u)", old_len, new_len, w->idx);
out:
	pthread_mutex_unlock(&w->cl_stack.lock);
	return ret;
}

static int init_clients(struct server_wrk *w)
{
	struct client_state **clients;
	uint32_t i;
	int ret;

	ret = init_client_stack(w);
	if (ret)
		return ret;

	w->client_arr_size = NR_INIT_CLIENT_ARR;
	clients = calloc(w->client_arr_size, sizeof(*clients));
	if (!clients) {
		free_client_stack(w);
		return -ENOMEM;
	}

	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = alloc_client_state();
		if (!c) {
			while (i--)
				free(clients[i]);
			free(clients);
			return -ENOMEM;
		}

		c->idx = i;
		clients[i] = c;
	}

	w->clients = clients;
	return 0;
}

static void put_client_slot_no_epoll(struct server_wrk *w, struct client_state *c);

static void close_all_clients(struct server_wrk *w)
{
	uint32_t i;

	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = w->clients[i];

		if (c->is_used) {
			put_client_slot_no_epoll(w, c);
			assert(!c->is_used);
			assert(c->client_ep.fd < 0);
			assert(c->target_ep.fd < 0);
			assert(!c->client_ep.buf);
			assert(!c->target_ep.buf);
		} else {
			assert(c->client_ep.fd < 0);
			assert(c->target_ep.fd < 0);

			if (c->target_ep.buf) {
				free(c->target_ep.buf);
				c->target_ep.buf = NULL;
			}

			if (c->client_ep.buf) {
				free(c->client_ep.buf);
				c->client_ep.buf = NULL;
			}
		}
	}
}

static void free_clients(struct server_wrk *w)
{
	uint32_t i;

	if (!w->clients)
		return;

	close_all_clients(w);
	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = w->clients[i];

		if (c) {
			free(c);
			w->clients[i] = NULL;
		}
	}

	free(w->clients);
	w->clients = NULL;
	free_client_stack(w);
}

static int handle_epoll_ctl_err(const char *op, int ret, int epl_fd, int fd)
{
	pr_error("Failed to %s FD %d in epoll (%d): %s", op, fd, epl_fd, strerror(ret));
	assert(0);
	return -ret;
}

static int epoll_add(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev))
		ret = handle_epoll_ctl_err("add", errno, ep_fd, fd);

	return ret;
}

static int epoll_del(int ep_fd, int fd)
{
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, NULL))
		ret = handle_epoll_ctl_err("del", errno, ep_fd, fd);

	return ret;
}

static int epoll_mod(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &ev))
		ret = handle_epoll_ctl_err("mod", errno, ep_fd, fd);

	return ret;
}

static int set_fd_nonblock(int fd)
{
	int flags, ret;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		ret = -errno;
		pr_error("Failed to get FD flags: %s", strerror(-ret));
		return ret;
	}

	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret) {
		ret = -errno;
		pr_error("Failed to set FD flags: %s", strerror(-ret));
		return ret;
	}

	return 0;
}

static int init_epoll(struct server_wrk *w)
{
	int ep_fd, ev_fd, ret;
	union epoll_data data;

	ep_fd = epoll_create(16);
	if (ep_fd < 0) {
		ret = -errno;
		pr_error("Failed to create epoll FD: %s", strerror(-ret));
		return ret;
	}

	ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ev_fd < 0) {
		ret = -errno;
		pr_error("Failed to create event FD: %s", strerror(-ret));
		close(ep_fd);
		return ret;
	}

	ret = set_fd_nonblock(ev_fd);
	if (ret) {
		close(ev_fd);
		close(ep_fd);
		return ret;
	}

	w->ep_fd = ep_fd;
	w->ev_fd = ev_fd;

	data.u64 = EPL_EV_EVENTFD;
	ret = epoll_add(ep_fd, ev_fd, EPOLLIN, data);
	if (ret) {
		close(ev_fd);
		close(ep_fd);
		w->ev_fd = -1;
		w->ep_fd = -1;
		return ret;
	}

	w->ep_timeout = 5000;
	return 0;
}

static void free_epoll(struct server_wrk *w)
{
	if (w->ep_fd >= 0)
		close(w->ep_fd);

	if (w->ev_fd >= 0)
		close(w->ev_fd);
}

static int init_timer(struct server_wrk *w)
{
	union epoll_data data;
	int ret;

	if (!w->ctx->need_timer) {
		w->timer_fd = -1;
		return 0;
	}

	ret = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (ret < 0) {
		ret = -errno;
		pr_error("Failed to create timer FD: %s", strerror(-ret));
		return ret;
	}

	w->timer_fd = ret;
	data.u64 = EPL_EV_TIMERFD;
	ret = epoll_add(w->ep_fd, ret, EPOLLIN, data);
	if (ret)
		return ret;

	w->next_timer_ns = 0;
	return 0;
}

static void free_timer(struct server_wrk *w)
{
	if (w->timer_fd >= 0) {
		close(w->timer_fd);
		w->timer_fd = -1;
	}
}

static void *worker_entry(void *arg);

static int init_worker(struct server_wrk *w, bool create_thread)
{
	int ret;

	w->timer_fd = -1;

	ret = init_clients(w);
	if (ret)
		return ret;

	ret = init_epoll(w);
	if (ret) {
		free_clients(w);
		return ret;
	}

	ret = init_timer(w);
	if (ret) {
		free_epoll(w);
		free_clients(w);
		return ret;
	}

	ret = pthread_mutex_init(&w->epass_mutex, NULL);
	if (ret) {
		free_timer(w);
		free_epoll(w);
		free_clients(w);
		return -ret;
	}

	if (create_thread) {
		ret = pthread_create(&w->thread, NULL, &worker_entry, w);
		if (ret) {
			pr_error("Failed to create worker thread %u: %s", w->idx, strerror(ret));
			ret = -ret;
			goto out_err;
		}
	} else {
		/*
		 * Add the main TCP socket which accepts new connections to the
		 * epoll instance in the main thread.
		 */
		union epoll_data data;

		data.u64 = EPL_EV_TCP_ACCEPT;
		ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
		if (ret)
			goto out_err;
	}

	return 0;

out_err:
	pthread_mutex_destroy(&w->epass_mutex);
	free_clients(w);
	free_epoll(w);
	free_timer(w);
	return ret;
}

static int send_event_fd(struct server_wrk *w)
{
	uint64_t val = 1;
	int ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_error("Failed to write to event FD: %s (thread %u)", strerror(ret), w->idx);
		return -ret;
	}

	return 0;
}

static int consume_event_fd(struct server_wrk *w)
{
	uint64_t val;
	int ret;

	ret = read(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_error("Failed to read from event FD: %s (thread %u)", strerror(ret), w->idx);
		return -ret;
	}

	return 0;
}

static void free_worker(struct server_wrk *w)
{
	if (w->ctx && w->idx != 0) {
		w->ctx->should_stop = true;
		send_event_fd(w);
		pr_info("Joining worker thread %u...", w->idx);
		pthread_join(w->thread, NULL);
		pr_info("Worker thread %u joined", w->idx);
	}

	free_clients(w);
	free_epoll(w);
	free_timer(w);
	pthread_mutex_destroy(&w->epass_mutex);
}

static int init_workers(struct server_ctx *ctx)
{
	int ret = 0;
	uint32_t i;

	if (ctx->cfg.nr_workers < 1)
		ctx->cfg.nr_workers = 1;

	ctx->workers = calloc(ctx->cfg.nr_workers, sizeof(*ctx->workers));
	if (!ctx->workers)
		return -ENOMEM;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct server_wrk *w = &ctx->workers[i];
		bool create_thread = (i > 0);
		int ret;

		w->idx = i;
		w->ctx = ctx;
		ret = init_worker(w, create_thread);
		if (ret) {
			pr_error("Failed to initialize worker %u: %s", i, strerror(-ret));
			goto out_err;
		}
	}

	return 0;

out_err:
	while (i--)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
	return ret;
}

static void free_workers(struct server_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int init_ctx(struct server_ctx *ctx)
{
	struct server_cfg *cfg = &ctx->cfg;
	int ret;

	if ((cfg->up_limit && cfg->up_interval) || (cfg->down_limit && cfg->down_interval))
		ctx->need_timer = true;
	else
		ctx->need_timer = false;

	g_verbose = ctx->cfg.verbose;
	try_increase_rlimit_nofile();
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ret = init_socket(ctx);
	if (ret)
		return ret;

	ret = init_spd_map(ctx);
	if (ret) {
		free_socket(ctx);
		return ret;
	}

	ret = pthread_mutex_init(&ctx->accept_mutex, NULL);
	if (ret) {
		free_spd_map(ctx);
		free_socket(ctx);
		return -ret;
	}

	ret = init_workers(ctx);
	if (ret) {
		pthread_mutex_destroy(&ctx->accept_mutex);
		free_spd_map(ctx);
		free_socket(ctx);
		return ret;
	}

	return 0;
}

static void free_ctx(struct server_ctx *ctx)
{
	free_workers(ctx);
	pthread_mutex_destroy(&ctx->accept_mutex);
	free_spd_map(ctx);
	free_socket(ctx);
}

static inline void get_ip_ptr(const struct sockaddr_in46 *addr, const void **ptr,
			      size_t *len)
{
	if (addr->sa.sa_family == AF_INET) {
		*ptr = &addr->in4.sin_addr;
		*len = sizeof(addr->in4.sin_addr);
	} else {
		*ptr = &addr->in6.sin6_addr;
		*len = sizeof(addr->in6.sin6_addr);
	}
}

/*
 * MUST HOLD: map->lock when calling this function.
 */
static int get_bucket_index(struct ip_spd_map *map,
			    const struct sockaddr_in46 *key, uint32_t *idx)
{
	struct ht_data *data;
	const void *tkey;
	size_t tkey_len;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	ret = ht_lookup(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	*idx = data->u32;
	return 0;
}

/*
 * MUST HOLD: map->lock when calling this function.
 */
static int set_bucket_index(struct ip_spd_map *map,
			    const struct sockaddr_in46 *key,
			    uint32_t idx)
{
	struct ht_data data;
	const void *tkey;
	size_t tkey_len;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	data.u32 = idx;
	ret = ht_insert(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	return 0;
}

static void init_ip_spd_bucket(struct ip_spd_bucket *b)
{
	memset(b, 0, sizeof(*b));
}

static uint64_t get_time_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static void us_to_timespec(uint64_t us, struct timespec *ts)
{
	ts->tv_sec = us / 1000000;
	ts->tv_nsec = (us % 1000000) * 1000;
}

static struct ip_spd_bucket *get_ip_spd_bucket(struct server_wrk *w,
					       struct ip_spd_map *map,
					       const struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	uint32_t idx;

	if (!map->bucket_arr)
		return NULL;

	pthread_mutex_lock(&map->lock);
	if (!get_bucket_index(map, addr, &idx)) {
		b = map->bucket_arr[idx];
		pthread_mutex_unlock(&map->lock);
		atomic_fetch_add(&b->nr_conns, 1u);
		return b;
	}

	if (map->len == map->cap) {
		size_t new_cap = map->cap + (map->cap / 2) + 1;
		struct ip_spd_bucket **new_arr;

		new_arr = realloc(map->bucket_arr, new_cap * sizeof(*new_arr));
		if (!new_arr) {
			pthread_mutex_unlock(&map->lock);
			return NULL;
		}

		map->bucket_arr = new_arr;
		map->cap = new_cap;
	}

	b = calloc(1, sizeof(*b));
	if (!b) {
		pthread_mutex_unlock(&map->lock);
		return NULL;
	}

	init_ip_spd_bucket(b);
	map->bucket_arr[map->len] = b;
	if (set_bucket_index(map, addr, map->len)) {
		free(b);
		b = NULL;
	} else {
		struct server_cfg *cfg = &w->ctx->cfg;
		uint64_t now = get_time_us();
		uint64_t rvp = 1;

		map->len++;
		b->up_tkn.fill_intv = cfg->up_interval * 1000 * rvp;
		b->dn_tkn.fill_intv = cfg->down_interval * 1000 * rvp;
		b->up_tkn.max = cfg->up_limit * rvp;
		b->dn_tkn.max = cfg->down_limit * rvp;
		atomic_store_explicit(&b->up_tkn.tkn, b->up_tkn.max, memory_order_relaxed);
		atomic_store_explicit(&b->dn_tkn.tkn, b->dn_tkn.max, memory_order_relaxed);
		atomic_store_explicit(&b->up_tkn.last_fill, now, memory_order_relaxed);
		atomic_store_explicit(&b->dn_tkn.last_fill, now, memory_order_relaxed);
		atomic_store_explicit(&b->nr_conns, 1u, memory_order_relaxed);
	}

	pthread_mutex_unlock(&map->lock);
	return b;
}

static void put_ip_spd_bucket(struct ip_spd_map *map, struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	uint32_t idx;

	assert(map->bucket_arr);
	pthread_mutex_lock(&map->lock);
	if (get_bucket_index(map, addr, &idx)) {
		pthread_mutex_unlock(&map->lock);
		pr_error("Failed to put bucket index for %s", sockaddr_to_str(addr));
		return;
	}

	b = map->bucket_arr[idx];
	if (atomic_fetch_sub(&b->nr_conns, 1u) == 1) {
		const void *key;
		size_t key_len;

		get_ip_ptr(addr, &key, &key_len);
		ht_remove(&map->ht, key, key_len);
		map->bucket_arr[idx] = NULL;
		free(b);
	}

	/*
	 * Shrink the bucket array if it's too large.
	 */
	if ((map->cap - map->len) > 32) {
		struct ip_spd_bucket **new_arr;
		size_t new_cap = map->len;

		new_arr = realloc(map->bucket_arr, new_cap * sizeof(*new_arr));
		if (new_arr) {
			map->bucket_arr = new_arr;
			map->cap = new_cap;
		}
	}

	pthread_mutex_unlock(&map->lock);
}

static int get_client_slot(struct server_wrk *w, struct client_state **c)
{
	struct client_state *t;
	uint32_t idx;
	int ret;

	ret = pop_stack_u32(&w->cl_stack, &idx);
	if (ret) {
		ret = upsize_clients(w);
		if (ret)
			return ret;

		ret = pop_stack_u32(&w->cl_stack, &idx);
		if (ret)
			return ret;
	}

	t = w->clients[idx];
	if (!t) {
		push_stack_u32(&w->cl_stack, idx);
		return -ENOMEM;
	}

	assert(!t->is_used);
	assert(!t->spd);
	assert(t->client_ep.fd < 0);
	assert(t->client_ep.len == 0);
	assert(t->target_ep.fd < 0);
	assert(t->target_ep.len == 0);

	t->is_used = true;
	*c = t;
	atomic_fetch_add(&w->nr_online_clients, 1u);
	return 0;
}

static void __put_client_slot(struct server_wrk *w, struct client_state *c,
			      bool epl_del, bool preserve_buf)
{
	bool hess = false;
	int ret;

	if (epl_del) {
		pthread_mutex_lock(&w->epass_mutex);
		if (c->client_ep.fd >= 0) {
			ret = epoll_del(w->ep_fd, c->client_ep.fd);
			if (ret) {
				pr_error("client_ep epoll_del error: %s -> %s (ep_fd=%d; fd=%d)",
					sockaddr_to_str(&c->client_ep.addr),
					sockaddr_to_str(&c->target_ep.addr),
					w->ep_fd,
					c->client_ep.fd);
			}
			hess = true;
		}

		if (c->target_ep.fd >= 0) {
			ret = epoll_del(w->ep_fd, c->target_ep.fd);
			if (ret) {
				pr_error("target_ep epoll_del error: %s -> %s (ep_fd=%d; fd=%d)",
					sockaddr_to_str(&c->client_ep.addr),
					sockaddr_to_str(&c->target_ep.addr),
					w->ep_fd,
					c->target_ep.fd);
			}
			hess = true;
		}
		pthread_mutex_unlock(&w->epass_mutex);
	}

	if (hess) {
		pthread_mutex_lock(&w->ctx->accept_mutex);
		if (w->ctx->accept_stopped) {
			union epoll_data data;

			data.u64 = EPL_EV_TCP_ACCEPT;
			pr_info("Re-enabling accept() (thread %u)", w->idx);
			ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
			assert(!ret);

			w->ctx->accept_stopped = false;
			send_event_fd(&w->ctx->workers[0]);
		}
		pthread_mutex_unlock(&w->ctx->accept_mutex);
	}

	if (c->spd) {
		put_ip_spd_bucket(&w->ctx->spd_map, &c->client_ep.addr);
		c->spd = NULL;
	}

	if (c->client_ep.fd >= 0) {
		pr_infov("pcls: %s -> %s (fd=%d; tfd=%d; thread=%u)",
			 sockaddr_to_str(&c->client_ep.addr),
			 sockaddr_to_str(&c->target_ep.addr),
			 c->client_ep.fd,
			 c->target_ep.fd,
			 w->idx);
	}

	reset_client_state(c, preserve_buf, NR_INIT_RECV_BUF_BYTES);
	push_stack_u32(&w->cl_stack, c->idx);
	atomic_fetch_sub(&w->nr_online_clients, 1u);
	w->handle_events_should_stop = hess;
	(void)ret;
}

static void put_client_slot(struct server_wrk *w, struct client_state *c)
{
	__put_client_slot(w, c, true, true);
}

static void put_client_slot_no_epoll(struct server_wrk *w, struct client_state *c)
{
	__put_client_slot(w, c, false, false);
}

static struct server_wrk *pick_worker_for_new_conn(struct server_ctx *ctx)
{
	struct server_wrk *w = NULL;
	uint32_t i, min;

	w = &ctx->workers[0];
	min = atomic_load(&ctx->workers[0].nr_online_clients);
	for (i = 1; i < ctx->cfg.nr_workers; i++) {
		uint32_t nr;

		nr = atomic_load(&ctx->workers[i].nr_online_clients);
		if (nr < 5)
			return &ctx->workers[i];

		if (nr < min) {
			min = nr;
			w = &ctx->workers[i];
		}
	}

	return w;
}

static int get_target_addr(struct server_wrk *w, struct client_state *c,
			   struct sockaddr_in46 *addr)
{
	struct sockaddr_in46 *cfg_addr = &w->ctx->cfg.target_addr;
	socklen_t len;
	sa_family_t f;
	int ret;

	/*
	 * If the destination is 0.0.0.0 or [::], get the original
	 * destination address from the client using getsockopt().
	 */
	if (cfg_addr->sa.sa_family == AF_INET) {
		if (cfg_addr->in4.sin_addr.s_addr != INADDR_ANY) {
			*addr = *cfg_addr;
			return 0;
		}
	} else if (cfg_addr->sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&cfg_addr->in6.sin6_addr)) {
			*addr = *cfg_addr;
			return 0;
		}
	}

	f = w->ctx->cfg.bind_addr.sa.sa_family;
	if (f == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&c->client_ep.addr.in6.sin6_addr)) {
		len = sizeof(addr->in6);
		ret = getsockopt(c->client_ep.fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &addr->in6, &len);
		if (ret) {
			ret = -errno;
			pr_error("getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST): %s", strerror(-ret));
		}

		return ret;
	}

	len = sizeof(addr->in4);
	ret = getsockopt(c->client_ep.fd, SOL_IP, SO_ORIGINAL_DST, &addr->in4, &len);
	if (ret) {
		ret = -errno;
		pr_error("getsockopt(SOL_IP, SO_ORIGINAL_DST): %s", strerror(-ret));
	}
	return ret;
}

static inline void set_epoll_data(union epoll_data *data, struct client_state *c,
				  uint64_t ev_mask)
{
	data->u64 = 0;
	data->ptr = c;
	data->u64 |= ev_mask;
}

static int set_optional_sockopt(int fd)
{
	int p;

	/*
	 * Set TCP_NODELAY and TCP_QUICKACK.
	 */
	p = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &p, sizeof(p));
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &p, sizeof(p));
	return 0;
}

static int prepare_target_connect(struct server_wrk *w, struct client_state *c)
{
	struct sockaddr_in46 taddr;
	union epoll_data data;
	socklen_t len;
	int fd, ret;

	memset(&taddr, 0, sizeof(taddr));
	ret = get_target_addr(w, c, &taddr);
	if (ret)
		return ret;

	if (taddr.sa.sa_family == AF_INET6)
		len = sizeof(taddr.in6);
	else
		len = sizeof(taddr.in4);

	fd = socket(taddr.sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ret = errno;
		pr_error("Failed to create target socket: %s", strerror(ret));
		return -ret;
	}

	set_optional_sockopt(fd);

	if (w->ctx->cfg.out_mark) {
		uint32_t mark = w->ctx->cfg.out_mark;

		ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		if (ret) {
			ret = errno;
			pr_error("Failed to set SO_MARK on target socket: %s", strerror(ret));
			close(fd);
			return -ret;
		}
	}

	c->target_ep.fd = fd;
	c->target_ep.addr = taddr;

	pr_infov("ncon: %s -> %s (fd=%d; tfd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_ep.addr),
		 sockaddr_to_str(&c->target_ep.addr),
		 c->client_ep.fd,
		 c->target_ep.fd,
		 w->idx);

	ret = connect(fd, &taddr.sa, len);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			pr_error("Failed to connect to target: %s", strerror(ret));
			close(fd);
			return -ret;
		}
	}

	pthread_mutex_lock(&w->epass_mutex);
	c->target_ep.ep_mask = EPOLLOUT;
	set_epoll_data(&data, c, EPL_EV_TCP_TARGET_CONN);
	ret = epoll_add(w->ep_fd, c->target_ep.fd, c->target_ep.ep_mask, data);
	if (ret) {
		pthread_mutex_unlock(&w->epass_mutex);
		close(c->target_ep.fd);
		c->target_ep.fd = -1;
		return ret;
	}

	c->client_ep.ep_mask = 0;
	set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_DATA);
	ret = epoll_add(w->ep_fd, c->client_ep.fd, c->client_ep.ep_mask, data);
	if (ret) {
		pthread_mutex_unlock(&w->epass_mutex);
		close(c->target_ep.fd);
		c->target_ep.fd = -1;
		return ret;
	}
	send_event_fd(w);
	pthread_mutex_unlock(&w->epass_mutex);
	atomic_fetch_add(&w->nr_online_clients, 1u);
	return 0;
}

/*
 * @fd: The ownership is taken by give_client_fd_to_a_worker().
 */
static int give_client_fd_to_a_worker(struct server_ctx *ctx, int fd,
				      const struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	struct client_state *c;
	struct server_wrk *w;
	int r;

	w = pick_worker_for_new_conn(ctx);
	r = get_client_slot(w, &c);
	if (r) {
		close(fd);
		pr_error("get_client_slot(): %s", strerror(-r));
		return -ENOMEM;
	}

	b = get_ip_spd_bucket(w, &ctx->spd_map, addr);
	if (b)
		c->spd = b;

	c->client_ep.fd = fd;
	c->client_ep.addr = *addr;
	r = prepare_target_connect(w, c);
	if (r) {
		put_client_slot_no_epoll(w, c);
		return r;
	}

	return 0;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN || err == EINTR)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		pthread_mutex_lock(&w->ctx->accept_mutex);
		w->ctx->accept_stopped = true;
		pthread_mutex_unlock(&w->ctx->accept_mutex);
		return epoll_del(w->ep_fd, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static int handle_event_accept(struct server_wrk *w)
{
	static const uint32_t NR_MAX_ACCEPT_CYCLE = 32;
	struct server_ctx *ctx = w->ctx;
	struct sockaddr_in46 addr;
	uint32_t counter = 0;
	socklen_t len;
	int ret;

do_accept:
	memset(&addr, 0, sizeof(addr));
	if (ctx->cfg.bind_addr.sa.sa_family == AF_INET6)
		len = sizeof(addr.in6);
	else
		len = sizeof(addr.in4);

	ret = accept4(ctx->tcp_fd, &addr.sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (unlikely(ret < 0))
		return handle_accept_error(errno, w);

	set_optional_sockopt(ret);
	if (unlikely(len > sizeof(addr))) {
		pr_error("accept() returned invalid address length: %u", len);
		close(ret);
		return -EINVAL;
	}

	ret = give_client_fd_to_a_worker(w->ctx, ret, &addr);
	if (ret)
		return ret;

	if (++counter < NR_MAX_ACCEPT_CYCLE)
		goto do_accept;

	return 0;
}

static ssize_t do_ep_recv(struct client_endp *ep, size_t max_send_size)
{
	ssize_t ret;
	size_t len;
	char *buf;

	if (ep->len == ep->cap) {
		size_t new_cap;
		char *tmp;

		if (ep->cap == 0)
			new_cap = NR_INIT_RECV_BUF_BYTES;
		else
			new_cap = (ep->cap * 2u) + 1u;

		new_cap = MIN(new_cap, NR_MAX_RECV_BUF_BYTES);
		if (new_cap <= NR_MAX_RECV_BUF_BYTES) {
			tmp = realloc(ep->buf, new_cap);
			if (!tmp) {
				if (ep->cap > 0)
					return -ENOBUFS;
				pr_error("Failed to realloc receive buffer: %s", strerror(ENOMEM));
				return -ENOMEM;
			}

			ep->buf = tmp;
			ep->cap = new_cap;
		}
	}

	assert(ep->len <= ep->cap);
	assert(ep->buf);

	len = ep->cap - ep->len;
	buf = ep->buf + ep->len;
	len = MIN(len, max_send_size);
	if (len == 0)
		return -ENOBUFS;

	ret = recv(ep->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		pr_errorv("recv() from %s: %s", sockaddr_to_str(&ep->addr),
			  strerror(-ret));
		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	ep->len += (size_t)ret;
	return 0;
}

static ssize_t do_ep_send(struct client_endp *src, struct client_endp *dst,
			  size_t max_send)
{
	size_t len = MIN(src->len, max_send);
	char *buf = src->buf;
	ssize_t ret;
	size_t uret;

	if (!len)
		return 0;

	ret = send(dst->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		pr_errorv("send() to %s: %s", sockaddr_to_str(&dst->addr),
			  strerror(-ret));
		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	uret = (size_t)ret;
	if (uret < len) {
		src->len -= uret;
		memmove(buf, buf + uret, src->len);
		return ret;
	}

	src->len = 0;
	return ret;
}

static int apply_ep_mask(struct server_wrk *w, struct client_state *c,
			 struct client_endp *ep)
{
	union epoll_data data;

	if (&c->target_ep == ep)
		set_epoll_data(&data, c, (c->target_connected) ? EPL_EV_TCP_TARGET_DATA : EPL_EV_TCP_TARGET_CONN);
	else
		set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_DATA);

	return epoll_mod(w->ep_fd, ep->fd, ep->ep_mask, data);
}

enum size_direction {
	MAX_UP_SIZE,
	MAX_DN_SIZE
};

static int arm_timer(struct server_wrk *w)
{
	struct itimerspec its;
	uint64_t now, interval;
	int ret;

	if (!w->ctx->need_timer)
		return 0;

	now = get_time_us();
	ret = timerfd_settime(w->timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
	if (ret) {
		ret = -errno;
		pr_error("Failed to arm timer: %s", strerror(-ret));
	}

	return ret;
}

static size_t get_max_send_size(struct client_state *c, enum size_direction dir)
{
	static _Atomic(uint8_t) p;
	uint64_t cur, last, now, delta, fill, new_tkn;
	struct ip_spd_bucket *b = c->spd;
	struct client_endp *src;
	struct spd_tkn *tkn;

	if (dir == MAX_UP_SIZE) {
		src = &c->client_ep;
		tkn = &b->up_tkn;
	} else {
		src = &c->target_ep;
		tkn = &b->dn_tkn;
	}

	if (!b)
		return (size_t)~0ull;

	now  = get_time_us();
	cur  = atomic_load_explicit(&tkn->tkn, memory_order_relaxed);
	last = atomic_load_explicit(&tkn->last_fill, memory_order_relaxed);

	delta = now - last;
	fill = ((tkn->max * delta * tkn->fill_intv) / tkn->fill_intv) / tkn->fill_intv;

	if (fill < (100*1024))
		fill = 0;

	new_tkn = MIN(cur + fill, tkn->max);
	if (new_tkn > cur) {
		atomic_store_explicit(&tkn->tkn, new_tkn, memory_order_relaxed);
		atomic_store_explicit(&tkn->last_fill, now, memory_order_relaxed);
		cur = new_tkn;
	}

	if (p++ % 4 == 0)
		printf("%s cur=%lu; new_tkn=%lu; fill=%lu; delta=%lu;\n",
		       dir == MAX_UP_SIZE ? "UP" : "DN", cur, new_tkn, fill, delta);

	return cur;
}

static void consume_token(struct client_state *c, enum size_direction dir,
			  size_t size)
{
	struct ip_spd_bucket *b = c->spd;
	struct spd_tkn *tkn;

	if (!b)
		return;

	if (dir == MAX_UP_SIZE)
		tkn = &b->up_tkn;
	else
		tkn = &b->dn_tkn;

	atomic_fetch_sub(&tkn->tkn, size);
}

static ssize_t do_pipe_epoll_in(struct server_wrk *w, struct client_state *c,
				struct client_endp *src, struct client_endp *dst)
{
	__unused struct sockaddr_in46 *psrc = (src == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused struct sockaddr_in46 *pdst = (dst == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused const char *src_name = (src == &c->client_ep) ? "Client" : "Target";
	__unused const char *dst_name = (dst == &c->client_ep) ? "Client" : "Target";
	enum size_direction dir = (src == &c->client_ep) ? MAX_UP_SIZE : MAX_DN_SIZE;
	size_t max_send_size = get_max_send_size(c, dir);
	ssize_t sock_ret;
	int err;

	sock_ret = do_ep_recv(src, max_send_size);
	if (sock_ret < 0) {
		if (sock_ret == -EAGAIN)
			return 0;
		if (sock_ret != -ENOBUFS)
			return sock_ret;

		pr_vl_dbg(3, "Disabling EPOLLIN on src=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  src_name,
			  src->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		src->ep_mask &= ~EPOLLIN;
		err = apply_ep_mask(w, c, src);
		if (err)
			return (ssize_t)err;
	}

	if (dst->ep_mask & EPOLLOUT)
		return 0;
	if (dst == &c->target_ep && !c->target_connected)
		goto enable_out_dst;
	if (max_send_size == 0)
		goto enable_out_dst;

	sock_ret = do_ep_send(src, dst, max_send_size);
	if (sock_ret < 0 && sock_ret != -EAGAIN) {
		pr_vl_dbg(3, "po: send() to %s (fd=%d; psrc=%s; pdst=%s; thread=%u): %s",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx,
			  strerror((int)-sock_ret));

		return sock_ret;
	}

	if (sock_ret > 0)
		consume_token(c, dir, (size_t)sock_ret);

enable_out_dst:
	if (src->len > 0) {
		pr_vl_dbg(3, "Enabling  EPOLLOUT on dst=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		dst->ep_mask |= EPOLLOUT;
		err = apply_ep_mask(w, c, dst);
		if (err)
			return (ssize_t)err;
	}

	return sock_ret;
}

static ssize_t do_pipe_epoll_out(struct server_wrk *w, struct client_state *c,
				 struct client_endp *src, struct client_endp *dst)
{
	__unused struct sockaddr_in46 *psrc = (src == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused struct sockaddr_in46 *pdst = (dst == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused const char *src_name = (src == &c->client_ep) ? "Client" : "Target";
	__unused const char *dst_name = (dst == &c->client_ep) ? "Client" : "Target";
	enum size_direction dir = (src == &c->client_ep) ? MAX_UP_SIZE : MAX_DN_SIZE;
	size_t max_send_size = get_max_send_size(c, dir);
	size_t remain_bsize;
	ssize_t sock_ret;
	int err;

	sock_ret = do_ep_send(src, dst, max_send_size);
	if (sock_ret < 0 && sock_ret != -EAGAIN) {
		pr_vl_dbg(3, "po: send() to %s (fd=%d; psrc=%s; pdst=%s; thread=%u): %s",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx,
			  strerror((int)-sock_ret));
		return sock_ret;
	}

	if (sock_ret > 0)
		consume_token(c, dir, (size_t)sock_ret);

	if (src->len == 0) {
		pr_vl_dbg(3, "Disabling EPOLLOUT on dst=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		dst->ep_mask &= ~EPOLLOUT;
		err = apply_ep_mask(w, c, dst);
		if (err)
			return err;
	}

	remain_bsize = src->cap - src->len;
	if (remain_bsize > 0 && !(src->ep_mask & EPOLLIN)) {
		pr_vl_dbg(3, "Enabling  EPOLLIN on src=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  src_name,
			  src->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);
		src->ep_mask |= EPOLLIN;
		err = apply_ep_mask(w, c, src);
		if (err)
			return (ssize_t)err;
	}

	if (sock_ret == -EAGAIN)
		sock_ret = 0;

	return sock_ret;
}

static int handle_event_client_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("rhup: Client socket hit EPOLLERR|EPOLLHUP: %s -> %s (thread %u)", sockaddr_to_str(&c->client_ep.addr), sockaddr_to_str(&c->target_ep.addr), w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->client_ep, &c->target_ep);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->target_ep, &c->client_ep);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int handle_event_target_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("thup: Target socket hit EPOLLERR|EPOLLHUP: %s -> %s (thread %u)", sockaddr_to_str(&c->client_ep.addr), sockaddr_to_str(&c->target_ep.addr), w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->target_ep, &c->client_ep);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->client_ep, &c->target_ep);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int handle_event_target_conn(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	socklen_t len;
	int ret, tmp;

	tmp = 0;
	len = sizeof(tmp);
	ret = getsockopt(c->target_ep.fd, SOL_SOCKET, SO_ERROR, &tmp, &len);
	if (unlikely(tmp || !(events & EPOLLOUT))) {
		if (tmp < 0)
			tmp = -tmp;
		pr_error("Connect error: %s: %s", sockaddr_to_str(&c->target_ep.addr), strerror(tmp));
		return -ECONNRESET;
	}

	pthread_mutex_lock(&w->epass_mutex);
	c->target_connected = true;
	c->target_ep.ep_mask |= EPOLLIN;
	ret = apply_ep_mask(w, c, &c->target_ep);
	if (ret) {
		pthread_mutex_unlock(&w->epass_mutex);
		return ret;
	}

	if (!(c->client_ep.ep_mask & EPOLLIN)) {
		c->client_ep.ep_mask |= EPOLLIN;
		ret = apply_ep_mask(w, c, &c->client_ep);
		if (ret) {
			pthread_mutex_unlock(&w->epass_mutex);
			return ret;
		}
	}

	pthread_mutex_unlock(&w->epass_mutex);
	pr_infov("conn: %s -> %s (fd=%d; tfd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_ep.addr),
		 sockaddr_to_str(&c->target_ep.addr),
		 c->client_ep.fd,
		 c->target_ep.fd,
		 w->idx);

	return 0;
}

static int handle_event_timer(struct server_wrk *w)
{
	return 0;
}

static int handle_event(struct server_wrk *w, struct epoll_event *ev)
{
	uint64_t evt = GET_EPL_EV(ev->data.u64);
	int ret = 0;

	switch (evt) {
	case EPL_EV_EVENTFD:
		ret = consume_event_fd(w);
		break;
	case EPL_EV_TCP_ACCEPT:
		ret = handle_event_accept(w);
		break;
	case EPL_EV_TCP_CLIENT_DATA:
		ret = handle_event_client_data(w, ev);
		break;
	case EPL_EV_TCP_TARGET_DATA:
		ret = handle_event_target_data(w, ev);
		break;
	case EPL_EV_TCP_TARGET_CONN:
		ret = handle_event_target_conn(w, ev);
		break;
	case EPL_EV_TIMERFD:
		ret = handle_event_timer(w);
		break;
	default:
		pr_error("Unknown event type: %lu (thread %u)", evt, w->idx);
		return -EINVAL;
	}

	if (ret < 0) {
		switch (evt) {
		case EPL_EV_TCP_TARGET_CONN:
		case EPL_EV_TCP_CLIENT_DATA:
		case EPL_EV_TCP_TARGET_DATA:
			put_client_slot(w, GET_EPL_DT(ev->data.u64));
			ret = 0;
			break;
		default:
			break;
		}
	}

	return 0;
}

static int handle_events(struct server_wrk *w, int nr_events)
{
	int ret = 0;
	int i;

	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &w->events[i];

		ret = handle_event(w, ev);
		if (ret < 0)
			break;
		if (w->handle_events_should_stop)
			break;
	}

	return ret;
}

static int poll_events(struct server_wrk *w)
{
	struct epoll_event *ev = w->events;
	int ret;

	w->handle_events_should_stop = false;
	ret = epoll_wait(w->ep_fd, ev, NR_EPOLL_EVENTS, w->ep_timeout);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		pr_error("epoll_wait() failed: %s (thread %u)", strerror(-ret), w->idx);
		return ret;
	}

	return ret;
}

static void *worker_entry(void *arg)
{
	struct server_wrk *w = arg;
	struct server_ctx *ctx = w->ctx;
	int ret = 0;
	void *ptr;

	while (!ctx->should_stop) {
		ret = poll_events(w);
		if (ret < 0)
			break;

		ret = handle_events(w, ret);
		if (ret < 0)
			break;
	}

	ptr = (void *)(intptr_t)ret;
	return ptr;
}

static int run_ctx(struct server_ctx *ctx)
{
	intptr_t ret;
	void *tmp;

	tmp = worker_entry(&ctx->workers[0]);
	ret = (intptr_t)tmp;

	return (int)ret;
}

int main(int argc, char *argv[])
{
	struct server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ret = parse_args(argc, argv, &ctx.cfg);
	if (ret)
		return ret;

	ret = init_ctx(&ctx);
	if (ret)
		return ret;

	ret = run_ctx(&ctx);
	free_ctx(&ctx);
	return ret;
}
