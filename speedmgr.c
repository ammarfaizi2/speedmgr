// SPDX-License-Identifier: GPL-2.0-only

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

/*
 * The number of `struct epoll_event` array members.
 */
#define NR_EPOLL_EVENTS 128

/*
 * The number of initial client slots.
 */
#define NR_INIT_CLIENT_ARR_SIZE 32

#define INIT_RECV_BUF_SIZE 8192
#define MAX_RECV_BUF_RESIZE (1024*1024*128)

#define INIT_SPD_MAP_SIZE 32

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

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

static volatile bool *g_stop;
static uint8_t g_verbose;

#if 0
#define pr_debug(fmt, ...) printf("debug %d: " fmt "\n", gettid(), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do { } while (0)
#endif

#define pr_error(fmt, ...) printf("error: " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) printf("info: " fmt "\n", ##__VA_ARGS__)

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

struct ip_spd_bucket {
	_Atomic(uint64_t)	up_tkn;
	_Atomic(uint64_t)	dn_tkn;
	uint64_t		up_tkn_max;
	uint64_t		dn_tkn_max;
	_Atomic(uint16_t)	nr_conns;
};

struct ip_spd_map {
	ht_t	ht;
	size_t	cap;
	size_t	len;
	pthread_mutex_t	lock;
	struct ip_spd_bucket **bucket_arr;
	uint64_t up_limit;
	uint64_t up_interval;
	uint64_t down_limit;
	uint64_t down_interval;
};

struct client_endp {
	int		fd;
	uint32_t	ep_mask;
	size_t		len;
	size_t		cap;
	char		*buf;
};

struct client_state {
	struct client_endp	client;
	struct client_endp	target;
	uint32_t		idx;
	struct sockaddr_in46	client_addr;
	struct ip_spd_bucket	*spd;
	bool target_connected;
};

struct client_stack {
	pthread_mutex_t	lock;
	uint32_t	sp;
	uint32_t	bp;
	uint32_t	data[];
};

struct server_ctx;

/*
 * Each worker has its own epoll FD.
 */
struct server_wrk {
	int			ep_fd;
	int			ev_fd;
	int			ep_timeout;

	uint32_t		idx;
	uint32_t		client_arr_size;
	_Atomic(uint32_t)	nr_online_clients;

	pthread_t		thread;	
	struct server_ctx	*ctx;
	struct client_state	*clients;
	struct client_stack	*cl_stack;

	volatile bool		handle_events_should_stop;
	struct epoll_event	events[NR_EPOLL_EVENTS];
};

/*
 * Server configuration.
 */
struct server_cfg {
	uint8_t			verbose;
	int			backlog;
	uint32_t		nr_workers;
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
	int			tcp_fd;
	struct server_wrk	*workers;
	struct server_cfg	cfg;
	struct ip_spd_map	spd_map;
};

enum {
	EPL_EV_EVENTFD		= (0x0000ull << 48ull),
	EPL_EV_TCP_ACCEPT	= (0x0001ull << 48ull),
	EPL_EV_TCP_CLIENT_DATA	= (0x0002ull << 48ull),
	EPL_EV_TCP_TARGET_DATA	= (0x0003ull << 48ull),
	EPL_EV_TCP_TARGET_CONN	= (0x0004ull << 48ull),
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
	{ NULL,			0,			NULL,	0 },
};
static const char short_options[] = "hVw:b:t:vB:U:I:D:d:";

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
}

static int init_spd_map(struct server_ctx *ctx)
{
	struct ip_spd_map *map = &ctx->spd_map;
	struct server_cfg *cfg = &ctx->cfg;
	int ret;

	map->up_limit = cfg->up_limit;
	map->up_interval = cfg->up_interval;
	map->down_limit = cfg->down_limit;
	map->down_interval = cfg->down_interval;

	if (!(map->up_limit && map->up_interval && map->down_limit && map->down_interval)) {
		memset(map, 0, sizeof(*map));
		pr_infov("Speed limits are not set, speed limiter is disabled");
		return 0;
	}

	ret = ht_create(&map->ht);
	if (ret)
		return ret;

	map->cap = INIT_SPD_MAP_SIZE;
	map->len = 0;
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

	if (!map->bucket_arr)
		return;

	pthread_mutex_lock(&map->lock);
	for (i = 0; i < map->len; i++)
		free(map->bucket_arr[i]);
	free(map->bucket_arr);
	ht_destroy(&map->ht);
	pthread_mutex_unlock(&map->lock);
}

static void init_ip_spd_bucket(struct ip_spd_bucket *b)
{
	memset(b, 0, sizeof(*b));
}

static inline void get_ip_ptr(struct sockaddr_in46 *addr, void **ptr, size_t *len)
{
	if (addr->sa.sa_family == AF_INET) {
		*ptr = &addr->in4.sin_addr;
		*len = sizeof(addr->in4.sin_addr);
	} else {
		*ptr = &addr->in6.sin6_addr;
		*len = sizeof(addr->in6.sin6_addr);
	}
}

static const char *sockaddr_to_str(struct sockaddr_in46 *addr)
{
	static __thread char _buf[8][INET6_ADDRSTRLEN + sizeof("[]:65535")];
	static __thread uint8_t _counter;
	char *buf = _buf[_counter++ % ARRAY_SIZE(_buf)];

	if (addr->sa.sa_family == AF_INET6) {
		*buf = '[';
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf + 1, INET6_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), "]:%hu",
			 ntohs(addr->in6.sin6_port));
	} else {
		inet_ntop(AF_INET, &addr->in4.sin_addr, buf, INET_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), ":%hu",
			 ntohs(addr->in4.sin_port));
	}

	return buf;
}

// MUST HOLD: map->lock when calling this function.
static int get_bucket_index(struct ip_spd_map *map, struct sockaddr_in46 *key,
			    uint32_t *idx)
{
	struct ht_data *data;
	size_t tkey_len;
	void *tkey;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	ret = ht_lookup(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	*idx = data->u32;
	return 0;
}

// MUST HOLD: map->lock when calling this function.
static int set_bucket_index(struct ip_spd_map *map, struct sockaddr_in46 *key,
			    uint32_t idx)
{
	struct ht_data data;
	size_t tkey_len;
	void *tkey;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	data.u32 = idx;
	ret = ht_insert(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	return 0;
}

static struct ip_spd_bucket *get_ip_spd_bucket(struct ip_spd_map *map,
					       struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	uint32_t idx;

	if (!map->bucket_arr)
		return NULL;

	pthread_mutex_lock(&map->lock);
	if (!get_bucket_index(map, addr, &idx)) {
		b = map->bucket_arr[idx];
		atomic_fetch_add(&b->nr_conns, 1u);
		pthread_mutex_unlock(&map->lock);
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
		map->len++;
		atomic_fetch_add(&b->nr_conns, 1u);
		b->up_tkn_max = map->up_limit;
		b->dn_tkn_max = map->down_limit;
		atomic_store_explicit(&b->up_tkn, b->up_tkn_max, memory_order_relaxed);
		atomic_store_explicit(&b->dn_tkn, b->dn_tkn_max, memory_order_relaxed);
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
		size_t key_len;
		void *key;

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
	if (ret <= 0 || ret > 65535) {
		pr_error("Invalid port in the address and port combination: \"%s\"", str);
		pr_error("Port must be between 1 and 65535");
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

	cfg->backlog = 64;
	cfg->nr_workers = 4;
	cfg->verbose = 0;

	p.got_bind_addr = false;
	p.got_target_addr = false;
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
			break;
		case 'I':
			cfg->up_interval = strtoull(optarg, &t, 10);
			p.got_up_interval = true;
			break;
		case 'D':
			cfg->down_limit = strtoull(optarg, &t, 10);
			p.got_down_limit = true;
			break;
		case 'd':
			cfg->down_interval = strtoull(optarg, &t, 10);
			p.got_down_interval = true;
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

static int handle_epoll_ctl_err(const char *op, int ret, int epl_fd, int fd)
{
	pr_error("Failed to %s FD %d in epoll (%d): %s", op, fd, epl_fd, strerror(-ret));
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

static int init_socket(struct server_ctx *ctx)
{
	int tcp_fd, ret, family;
	socklen_t len;

	ctx->accept_stopped = false;
	family = ctx->cfg.bind_addr.sa.sa_family;
	tcp_fd = socket(family, SOCK_STREAM | SOCK_STREAM, 0);
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

static void free_client_stack(struct server_wrk *w)
{
	if (!w->cl_stack)
		return;

	pthread_mutex_lock(&w->cl_stack->lock);
	pthread_mutex_unlock(&w->cl_stack->lock);
	pthread_mutex_destroy(&w->cl_stack->lock);
	free(w->cl_stack);
	w->cl_stack = NULL;
}

static int __push_client_stack(struct client_stack *cs, uint32_t data)
{
	if (cs->sp == cs->bp)
		return -EAGAIN;

	cs->data[cs->sp++] = data;
	return 0;
}

static int push_client_stack(struct client_stack *cs, uint32_t data)
{
	int ret;

	pthread_mutex_lock(&cs->lock);
	ret = __push_client_stack(cs, data);
	pthread_mutex_unlock(&cs->lock);
	return ret;
}

static int __pop_client_stack(struct client_stack *cs, uint32_t *data)
{
	if (cs->sp == 0)
		return -EAGAIN;

	*data = cs->data[--cs->sp];
	return 0;
}

static int pop_client_stack(struct client_stack *cs, uint32_t *data)
{
	int ret;

	pthread_mutex_lock(&cs->lock);
	ret = __pop_client_stack(cs, data);
	pthread_mutex_unlock(&cs->lock);
	return ret;
}

static int init_client_stack(struct server_wrk *w)
{
	struct client_stack *cl_stack;
	size_t size;
	uint32_t i;
	int ret;

	size = sizeof(*cl_stack) + (sizeof(*cl_stack->data) * NR_INIT_CLIENT_ARR_SIZE);
	cl_stack = malloc(size);
	if (!cl_stack)
		return -ENOMEM;

	ret = pthread_mutex_init(&cl_stack->lock, NULL);
	if (ret) {
		pr_error("Failed to initialize client stack mutex: %s", strerror(ret));
		free(cl_stack);
		return -ret;
	}

	cl_stack->sp = 0;
	cl_stack->bp = NR_INIT_CLIENT_ARR_SIZE;
	for (i = NR_INIT_CLIENT_ARR_SIZE; i > 0; i--)
		__push_client_stack(cl_stack, i - 1);

	w->cl_stack = cl_stack;
	return 0;
}

static void init_client_endp(struct client_endp *e)
{
	e->fd = -1;
	e->ep_mask = 0;
	e->len = 0;
	e->cap = 0;
	e->buf = NULL;
}

static void init_client_state(struct client_state *c)
{
	init_client_endp(&c->client);
	init_client_endp(&c->target);
	c->target_connected = false;
	c->spd = NULL;
	memset(&c->client_addr, 0, sizeof(c->client_addr));
}

static int init_clients(struct server_wrk *w)
{
	struct client_state *clients;
	uint32_t i;
	int ret;

	ret = init_client_stack(w);
	if (ret)
		return ret;

	w->client_arr_size = NR_INIT_CLIENT_ARR_SIZE;
	clients = calloc(w->client_arr_size, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	for (i = 0; i < w->client_arr_size; i++) {
		init_client_state(&clients[i]);
		clients[i].idx = i;
	}

	w->clients = clients;
	return 0;
}

static void free_client_endp(struct client_endp *e)
{
	if (e->fd >= 0) {
		close(e->fd);
		e->fd = -1;
	}

	if (e->buf) {
		free(e->buf);
		e->buf = NULL;
		e->len = 0;
		e->cap = 0;
	}
}

static void close_all_client_fds(struct server_wrk *w)
{
	uint32_t i;

	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = &w->clients[i];

		free_client_endp(&c->client);
		free_client_endp(&c->target);
	}
}

static void free_clients(struct server_wrk *w)
{
	if (!w->clients)
		return;

	close_all_client_fds(w);
	free(w->clients);
	w->clients = NULL;
	free_client_stack(w);
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

static void *worker_func(void *data);

static int init_worker(struct server_wrk *w, bool create_thread)
{
	int ret;

	ret = init_clients(w);
	if (ret)
		return ret;

	ret = init_epoll(w);
	if (ret) {
		free_clients(w);
		return ret;
	}

	if (create_thread) {
		ret = pthread_create(&w->thread, NULL, &worker_func, w);
		if (ret) {
			pr_error("Failed to create worker thread %u: %s", w->idx, strerror(ret));
			free_clients(w);
			free_epoll(w);
			return ret;
		}
	} else {
		union epoll_data data;

		data.u64 = EPL_EV_TCP_ACCEPT;
		ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
		if (ret) {
			free_clients(w);
			free_epoll(w);
			return ret;
		}
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
}

static int init_workers(struct server_ctx *ctx)
{
	int ret = 0;
	uint32_t i;

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
	int ret;

	g_verbose = ctx->cfg.verbose;
	try_increase_rlimit_nofile();
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ret = init_spd_map(ctx);
	if (ret)
		return ret;

	ret = init_socket(ctx);
	if (ret) {
		free_spd_map(ctx);
		return ret;
	}

	ret = init_workers(ctx);
	if (ret) {
		free_spd_map(ctx);
		free_socket(ctx);
		return ret;
	}

	return 0;
}

static void free_ctx(struct server_ctx *ctx)
{
	free_workers(ctx);
	free_socket(ctx);
	free_spd_map(ctx);
}

static struct client_state *get_free_client_slot(struct server_wrk *w)
{
	struct client_state *c;
	uint32_t idx;
	int ret;

	ret = pop_client_stack(w->cl_stack, &idx);
	if (ret)
		return NULL;

	c = &w->clients[idx];
	assert(c->client.fd < 0);
	assert(c->target.fd < 0);
	assert(!c->target_connected);
	assert(c->idx == idx);
	assert(!c->spd);
	return c;
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


static void put_client_slot(struct server_wrk *w, struct client_state *c)
{
	bool hess = false;
	int ret;

	if (c->client.fd >= 0) {
		pr_infov("Closing client FD %d (src: %s) (thread %u)", c->client.fd, sockaddr_to_str(&c->client_addr), w->idx);
		ret = epoll_del(w->ep_fd, c->client.fd);
		assert(!ret);
		free_client_endp(&c->client);
		hess = true;
	}

	if (c->target.fd >= 0) {
		ret = epoll_del(w->ep_fd, c->target.fd);
		assert(!ret);
		free_client_endp(&c->target);
		hess = true;
	}

	if (hess && w->ctx->accept_stopped) {
		union epoll_data data;

		pr_info("Re-enabling accept() (thread %u)", w->idx);
		data.u64 = EPL_EV_TCP_ACCEPT;
		ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
		assert(!ret);

		w->ctx->accept_stopped = false;
		send_event_fd(&w->ctx->workers[0]);
	}

	w->handle_events_should_stop = hess;
	c->target_connected = false;
	if (c->spd) {
		put_ip_spd_bucket(&w->ctx->spd_map, &c->client_addr);
		c->spd = NULL;
	}
	memset(&c->client_addr, 0, sizeof(c->client_addr));
	ret = push_client_stack(w->cl_stack, c->idx);
	atomic_fetch_sub(&w->nr_online_clients, 1u);
	assert(!ret);
	(void)ret;
}

static int prepare_target_connect(struct server_wrk *w, struct client_state *c)
{
	struct sockaddr_in46 *taddr = &w->ctx->cfg.target_addr;
	union epoll_data data;
	socklen_t len;
	int fd, ret;

	if (taddr->sa.sa_family == AF_INET6)
		len = sizeof(taddr->in6);
	else
		len = sizeof(taddr->in4);

	fd = socket(taddr->sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = errno;
		pr_error("Failed to create target socket: %s", strerror(ret));
		return -ret;
	}

#ifdef TCP_NODELAY
	ret = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret));
#endif

	ret = connect(fd, &taddr->sa, len);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			pr_error("Failed to connect to target: %s", strerror(ret));
			close(fd);
			return -ret;
		}
	}

	c->target.fd = fd;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EV_TCP_CLIENT_DATA;
	c->client.ep_mask = 0;
	ret = epoll_add(w->ep_fd, c->client.fd, c->client.ep_mask, data);
	if (ret)
		return ret;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EV_TCP_TARGET_CONN;
	c->target.ep_mask = EPOLLOUT | EPOLLIN;
	ret = epoll_add(w->ep_fd, c->target.fd, c->target.ep_mask, data);
	if (ret)
		return ret;

	send_event_fd(w);
	pr_debug("Preparing forward conn from %s to %s (thread %u)", sockaddr_to_str(&c->client_addr), sockaddr_to_str(taddr), w->idx);
	return 0;
}

static int give_client_fd_to_a_worker(struct server_ctx *ctx, int fd,
				      struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	struct client_state *c;
	struct server_wrk *w;
	int ret;

	w = pick_worker_for_new_conn(ctx);
	c = get_free_client_slot(w);
	if (!c) {
		pr_error("No free client slots available");
		return -ENOMEM;
	}

	c->client.fd = fd;
	c->client_addr = *addr;
	b = get_ip_spd_bucket(&ctx->spd_map, &c->client_addr);
	if (b)
		c->spd = b;

	ret = prepare_target_connect(w, c);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	atomic_fetch_add(&w->nr_online_clients, 1u);
	return 0;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		w->ctx->accept_stopped = true;
		return epoll_del(w->ep_fd, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static int handle_event_accept(struct server_wrk *w)
{
	struct server_ctx *ctx = w->ctx;
	struct sockaddr_in46 addr;
	socklen_t len;
	int ret, fd;

	memset(&addr, 0, sizeof(addr));
	if (ctx->cfg.bind_addr.sa.sa_family == AF_INET6)
		len = sizeof(addr.in6);
	else
		len = sizeof(addr.in4);

	ret = accept(ctx->tcp_fd, &addr.sa, &len);
	if (unlikely(ret < 0))
		return handle_accept_error(errno, w);

	if (unlikely(len > sizeof(addr))) {
		pr_error("accept() returned invalid address length: %u", len);
		close(ret);
		return -EINVAL;
	}

	pr_infov("New connection from %s", sockaddr_to_str(&addr));
	fd = ret;
	ret = give_client_fd_to_a_worker(w->ctx, fd, &addr);
	if (ret)
		close(fd);

	return ret;
}

static int toggle_ep_event(struct server_wrk *w, struct client_state *cl,
			   struct client_endp *ep, uint32_t tmask, bool enable)
{
	union epoll_data data;
	uint32_t mask;
	int ret;

	mask = ep->ep_mask;
	if (enable) {
		if (mask & tmask)
			return 0;
		mask |= tmask;
	} else {
		if (!(mask & tmask))
			return 0;
		mask &= ~tmask;
	}

	data.u64 = 0;
	data.ptr = cl;
	if (ep == &cl->client)
		data.u64 |= EPL_EV_TCP_CLIENT_DATA;
	else
		data.u64 |= EPL_EV_TCP_TARGET_DATA;

	ret = epoll_mod(w->ep_fd, ep->fd, mask, data);
	if (ret)
		return ret;

	ep->ep_mask = mask;
	return 0;
}

static int toggle_epoll_in(struct server_wrk *w, struct client_state *cl,
			   struct client_endp *ep, bool enable)
{
	return toggle_ep_event(w, cl, ep, EPOLLIN, enable);
}

static int toggle_epoll_out(struct server_wrk *w, struct client_state *cl,
			    struct client_endp *ep, bool enable)
{
	return toggle_ep_event(w, cl, ep, EPOLLOUT, enable);
}

static int handle_event_target_conn(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	union epoll_data data;
	socklen_t len;
	int ret, tmp;

	tmp = 0;
	len = sizeof(tmp);
	ret = getsockopt(c->target.fd, SOL_SOCKET, SO_ERROR, &tmp, &len);
	if (unlikely(tmp || !(events & EPOLLOUT))) {
		if (tmp < 0)
			tmp = -tmp;
		pr_error("Failed to get target socket error: %s (thread %u)", strerror(tmp), w->idx);
		return -ECONNRESET;
	}

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EV_TCP_TARGET_DATA;
	c->target.ep_mask = EPOLLIN;
	ret = epoll_mod(w->ep_fd, c->target.fd, c->target.ep_mask, data);
	if (ret)
		return ret;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EV_TCP_CLIENT_DATA;
	c->client.ep_mask = EPOLLIN;
	ret = epoll_mod(w->ep_fd, c->client.fd, c->client.ep_mask, data);
	if (ret)
		return ret;

	c->target_connected = true;
	pr_infov("Target connection established (thread %u)", w->idx);
	return 0;
}

static ssize_t do_ep_recv(struct client_endp *ep)
{
	ssize_t ret;
	size_t len;
	char *buf;

	if (ep->len == ep->cap) {
		size_t new_cap;
		char *tmp;

		if (ep->cap == 0)
			new_cap = INIT_RECV_BUF_SIZE;
		else
			new_cap = ep->cap + (ep->cap / 2) + 1;

		if (new_cap <= MAX_RECV_BUF_RESIZE) {
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
	if (len == 0)
		return -ENOBUFS;

	len = ep->cap - ep->len;
	buf = ep->buf + ep->len;
	ret = recv(ep->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	ep->len += (size_t)ret;
	return 0;
}

static ssize_t do_ep_send(struct client_endp *src, struct client_endp *dst)
{
	ssize_t ret;
	size_t len;
	char *buf;

	if (src->len == 0)
		return 0;

	len = src->len;
	buf = src->buf;
	ret = send(dst->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		pr_error("Failed to send data: %s", strerror(-ret));
		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	if ((size_t)ret < len) {
		memmove(buf, buf + ret, len - (size_t)ret);
		src->len -= (size_t)ret;
		return -EAGAIN;
	}

	src->len = 0;
	return ret;
}

static int do_pipe_epoll_in(struct server_wrk *w, struct client_state *c,
			    struct client_endp *src, struct client_endp *dst)
{
	ssize_t ret;

	ret = do_ep_recv(src);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return 0;

		if (ret == -ENOBUFS) {
			pr_infov("%s recv buffer is full, disabling EPOLLIN (thread %u)", src == &c->client ? "Client" : "Target", w->idx);
			return toggle_epoll_in(w, c, src, false);
		}

		return ret;
	}

	if (dst == &c->target && !c->target_connected)
		return toggle_epoll_out(w, c, dst, true);

	if (dst->ep_mask & EPOLLOUT)
		return 0;

	ret = do_ep_send(src, dst);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			pr_error("Failed to send data: %s", strerror(-ret));
			return ret;
		}

		pr_infov("%s send buffer is full, enabling EPOLLOUT (thread %u)", dst == &c->client ? "Client" : "Target", w->idx);
		ret = toggle_epoll_out(w, c, dst, true);
		if (ret)
			return ret;
	}

	return 0;
}

static int do_pipe_epoll_out(struct server_wrk *w, struct client_state *c,
			     struct client_endp *src, struct client_endp *dst)
{
	ssize_t ret;

	ret = do_ep_send(src, dst);
	if (ret < 0 && ret != -EAGAIN) {
		pr_error("Failed to send data: %s", strerror(-ret));
		return ret;
	}

	if (src->len == 0) {
		pr_infov("%s send buffer has been flushed, disabling EPOLLOUT (thread %u)", src == &c->client ? "Client" : "Target", w->idx);
		ret = toggle_epoll_out(w, c, dst, false);
		if (ret)
			return ret;
	}

	if ((src->cap - src->len) > 0 && !(src->ep_mask & EPOLLIN)) {
		pr_infov("%s recv buffer has space, enabling EPOLLIN (thread %u)", src == &c->client ? "Client" : "Target", w->idx);
		ret = toggle_epoll_in(w, c, src, true);
		if (ret)
			return ret;
	}

	return 0;
}

static int handle_event_client_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("Client socket hit (EPOLLERR|EPOLLHUP) (thread %u)", w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->client, &c->target);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->target, &c->client);
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
		pr_errorv("Client socket hit (EPOLLERR|EPOLLHUP) (thread %u)", w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->target, &c->client);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->client, &c->target);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int handle_event(struct server_wrk *w, struct epoll_event *ev)
{
	uint64_t evt = GET_EPL_EV(ev->data.u64);
	int ret;

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

static void *worker_func(void *arg)
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

	tmp = worker_func(&ctx->workers[0]);
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
