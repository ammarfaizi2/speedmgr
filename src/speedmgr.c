// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ip_map.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <sys/resource.h>
#include <sys/timerfd.h>
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

#define SPEEDMGR_DEBUG		1
#define NR_CLIENTS		4096
#define NR_INIT_BUCKETS		4
#define SPLICE_BUF_SIZE		8192

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST		80
#endif

#if SPEEDMGR_DEBUG
#define pr_debug(fmt, ...) printf("debug: " fmt "\n", ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do {} while (0)
#endif

#define pr_info(fmt, ...)	printf("info: " fmt "\n", ##__VA_ARGS__)
#define pr_error(fmt, ...)	printf("error: " fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...)	printf("warn: " fmt "\n", ##__VA_ARGS__)
#define pr_vinfo(fmt, ...)	do { if (g_verbose) pr_info(fmt, ##__VA_ARGS__); } while (0)
#define pr_verror(fmt, ...)	do { if (g_verbose) pr_error(fmt, ##__VA_ARGS__); } while (0)
#define pr_vwarn(fmt, ...)	do { if (g_verbose) pr_warn(fmt, ##__VA_ARGS__); } while (0)
#define pr_vdebug(fmt, ...)	do { if (g_verbose) pr_debug(fmt, ##__VA_ARGS__); } while (0)

#define NR_EPOLL_EVENTS		64

static volatile bool *g_stop;
static uint8_t g_verbose;

struct sockaddr_in46 {
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
};

struct in46_addr {
	union {
		struct in_addr in4;
		struct in6_addr in6;
	};
};

struct client_state;

struct token_bucket {
	pthread_mutex_t		lock;
	int			timer_fd;
	_Atomic(uint64_t)	upload_tokens;
	_Atomic(uint64_t)	download_tokens;
	uint64_t		max_upload_tokens;
	uint64_t		max_download_tokens;
	uint32_t		ref_cnt;	/* Protected by lock. */
	uint32_t		nr_clients;	/* Protected by lock. */
	struct client_state	**clients;	/* Protected by lock. */
	struct in46_addr	addr;
};

struct rate_limit {
	pthread_mutex_t		lock;
	uint32_t		nr_tbuckets;
	uint32_t		nr_allocated;
	struct token_bucket	**tbuckets;
	ip_map_t		ip_map;
};

struct client_state {
	int			client_fd;
	int			target_fd;
	uint32_t		cpoll_mask;
	uint32_t		tpoll_mask;
	uint32_t		idx;
	size_t			cbuf_len;
	size_t			tbuf_len;
	char			*cbuf;
	char			*tbuf;
	struct sockaddr_in46	client_addr;
	struct token_bucket	*tbucket;
	bool			is_rate_limited;
};

struct client_stack {
	pthread_mutex_t	lock;
	uint32_t	sp;
	uint32_t	bp;
	uint32_t	data[];
};

struct server_ctx;

/*
 * Each worker has its epoll FD.
 */
struct server_wrk {
	int			ep_fd;
	int			ev_fd;
	int			ep_timeout;
	uint32_t		idx;
	uint32_t		nr_clients;
	_Atomic(uint32_t)	nr_active_clients;
	struct server_ctx	*ctx;
	struct client_stack	*cl_stack;
	struct client_state	*clients;
	struct epoll_event	events[NR_EPOLL_EVENTS];
	volatile bool		handle_events_should_break;
	pthread_t		thread;
};

struct server_cfg {
	uint8_t			verbose;
	bool			using_rate_limit;
	bool			using_tcp;
	bool			using_udp;
	int			tcp_backlog;
	uint32_t		nr_workers;
	uint64_t		max_upload_speed;
	uint64_t		max_download_speed;
	uint32_t		interval_ms;
	struct sockaddr_in46	tcp_bind_addr;
	struct sockaddr_in46	tcp_target_addr;
	struct sockaddr_in46	udp_bind_addr;
	struct sockaddr_in46	udp_target_addr;
};

struct server_ctx {
	volatile bool		should_stop;
	volatile bool		accept_need_rearm;
	int			tcp_fd;
	int			udp_fd;
	uint32_t		nr_workers;
	struct server_wrk	*workers;
	struct rate_limit	rl;
	struct server_cfg	cfg;
};

enum {
	EPL_DT_EVENT_FD = 0,
	EPL_DT_TCP_FD   = 1,
	EPL_DT_UDP_FD   = 2,
};

enum {
	EPL_DT_MASK_TARGET_TCP_CONNECT = (0x0001ull << 48ull),
	EPL_DT_MASK_TARGET_TCP_DATA    = (0x0002ull << 48ull),
	EPL_DT_MASK_CLIENT_TCP_DATA    = (0x0003ull << 48ull),
	EPL_DT_MASK_TARGET_UDP_DATA    = (0x0004ull << 48ull),
	EPL_DT_MASK_CLIENT_UDP_DATA    = (0x0005ull << 48ull),
	EPL_DT_MASK_TIMER              = (0x0006ull << 48ull),
};

#define EPL_DT_MASK_ALL		(0xffffull << 48ull)

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif


static struct option long_options[] = {
	{"help",		no_argument,		0, 'h'},
	{"version",		no_argument,		0, 'V'},
	{"verbose",		no_argument,		0, 'v'},
	{"workers",		required_argument,	0, 'w'},
	{"tcp-backlog",		required_argument,	0, 'b'},
	{"tcp-bind",		required_argument,	0, 'B'},
	{"tcp-target",		required_argument,	0, 'T'},
	{"udp-bind",		required_argument,	0, 'U'},
	{"udp-target",		required_argument,	0, 'W'},
	{"max-upload-speed",	required_argument,	0, 'u'},
	{"max-download-speed",	required_argument,	0, 'd'},
	{"interval",		required_argument,	0, 'i'},
	{0, 0, 0, 0}
};

static const char short_options[] = "hVvw:b:B:T:U:W:u:d:i:";

static void show_help(const char *app)
{
	printf("\n");
	printf("Usage: %s [options]\n\n", app);
	printf(" Options:\n");
	printf("  -h, --help\t\t\tShow this help message and exit.\n");
	printf("  -V, --version\t\t\tShow version information and exit.\n");
	printf("  -v, --verbose\t\t\tVerbose mode.\n");
	printf("  -w, --workers\t\t\tNumber of workers.\n\n");

	printf(" Socket options:\n");
	printf("  -b, --tcp-backlog\t\tTCP backlog size.\n");
	printf("  -B, --tcp-bind\t\tTCP bind address.\n");
	printf("  -T, --tcp-target\t\tTCP target address.\n");
	printf("  -U, --udp-bind\t\tUDP bind address.\n");
	printf("  -W, --udp-target\t\tUDP target address.\n\n");

	printf(" Rate limit options:\n");
	printf("  -u, --max-upload-speed\tMax upload speed in bytes per <interval> milliseconds.\n");
	printf("  -d, --max-download-speed\tMax download speed in bytes per <interval> milliseconds.\n");
	printf("  -i, --interval\t\tInterval in milliseconds.\n");
}

static void show_version(void)
{
	printf("speedmgr version 0.0.1\n");
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

static void set_default_server_cfg(struct server_cfg *cfg)
{
	cfg->verbose = 0;
	cfg->using_rate_limit = false;
	cfg->tcp_backlog = 128;
	cfg->nr_workers = 4;
	cfg->max_upload_speed = 0;
	cfg->max_download_speed = 0;
	cfg->interval_ms = 1000;
	memset(&cfg->tcp_bind_addr, 0, sizeof(cfg->tcp_bind_addr));
	memset(&cfg->tcp_target_addr, 0, sizeof(cfg->tcp_target_addr));
	memset(&cfg->udp_bind_addr, 0, sizeof(cfg->udp_bind_addr));
	memset(&cfg->udp_target_addr, 0, sizeof(cfg->udp_target_addr));
}

static int parse_args(int argc, char *argv[], struct server_cfg *cfg)
{
	struct parse_state {
		bool got_tcp_bind_addr;
		bool got_tcp_target_addr;
		bool got_udp_bind_addr;
		bool got_udp_target_addr;
		bool got_max_upload_speed;
		bool got_max_download_speed;
		bool got_interval;
	} p;

	memset(&p, 0, sizeof(p));
	while (1) {
		int c, tmp;

		c = getopt_long(argc, argv, short_options, long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
			break;

		case 'v':
			cfg->verbose++;
			break;

		case 'w':
			tmp = atoi(optarg);
			if (tmp < 1 || tmp > 1024) {
				pr_error("Invalid number of workers: %d", tmp);
				return -EINVAL;
			}

			cfg->nr_workers = (uint32_t)tmp;
			break;

		case 'b':
			tmp = atoi(optarg);
			if (tmp < 1 || tmp > 1024) {
				pr_error("Invalid TCP backlog size: %d", tmp);
				return -EINVAL;
			}

			cfg->tcp_backlog = tmp;
			break;

		case 'B':
			if (parse_addr_and_port(optarg, &cfg->tcp_bind_addr) < 0)
				return -EINVAL;

			p.got_tcp_bind_addr = true;
			cfg->using_tcp = true;
			break;

		case 'T':
			if (parse_addr_and_port(optarg, &cfg->tcp_target_addr) < 0)
				return -EINVAL;

			p.got_tcp_target_addr = true;
			break;

		case 'U':
			if (parse_addr_and_port(optarg, &cfg->udp_bind_addr) < 0)
				return -EINVAL;

			p.got_udp_bind_addr = true;
			cfg->using_udp = true;
			break;

		case 'W':
			if (parse_addr_and_port(optarg, &cfg->udp_target_addr) < 0)
				return -EINVAL;

			p.got_udp_target_addr = true;
			break;

		case 'u':
			cfg->max_download_speed = (uint64_t)strtoull(optarg, NULL, 10);
			p.got_max_download_speed = true;
			break;

		case 'd':
			cfg->max_upload_speed = (uint64_t)strtoull(optarg, NULL, 10);
			p.got_max_upload_speed = true;
			break;

		case 'i':
			tmp = atoi(optarg);
			if (tmp < 1 || tmp > 10000) {
				pr_error("Invalid interval: %d", tmp);
				return -EINVAL;
			}

			cfg->interval_ms = (uint32_t)tmp;
			p.got_interval = true;
			break;

		case '?':
			show_help(argv[0]);
			exit(EXIT_FAILURE);
			break;

		default:
			pr_error("Unknown option: %c", c);
			show_help(argv[0]);
			return -EINVAL;
		}
	}

	if (p.got_tcp_bind_addr || p.got_tcp_target_addr) {
		if (!p.got_tcp_bind_addr) {
			pr_error("Missing TCP bind address");
			return -EINVAL;
		}

		if (!p.got_tcp_target_addr) {
			pr_error("Missing TCP target address");
			return -EINVAL;
		}
	}

	if (p.got_udp_bind_addr || p.got_udp_target_addr) {
		if (!p.got_udp_bind_addr) {
			pr_error("Missing UDP bind address");
			return -EINVAL;
		}

		if (!p.got_udp_target_addr) {
			pr_error("Missing UDP target address");
			return -EINVAL;
		}
	}

	if (!p.got_udp_bind_addr && !p.got_tcp_bind_addr) {
		pr_error("Missing TCP or UDP bind address");
		return -EINVAL;
	}

	if (p.got_max_download_speed || p.got_max_upload_speed || p.got_interval) {
		if (!p.got_max_download_speed) {
			pr_error("Missing max download speed");
			return -EINVAL;
		}

		if (!p.got_max_upload_speed) {
			pr_error("Missing max upload speed");
			return -EINVAL;
		}

		if (!p.got_interval) {
			pr_error("Missing interval");
			return -EINVAL;
		}

		cfg->using_rate_limit = true;
	}

	return 0;
}

static void set_default_server_ctx(struct server_ctx *ctx)
{
	ctx->should_stop = false;
	ctx->accept_need_rearm = false;
	ctx->tcp_fd = -1;
	ctx->udp_fd = -1;
	ctx->nr_workers = 0;
	ctx->workers = NULL;
	ctx->rl.nr_tbuckets = 0;
	ctx->rl.nr_allocated = 0;
	ctx->rl.tbuckets = NULL;
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

static void signal_handler(int sig)
{
	*g_stop = true;
	putchar('\n');
	(void)sig;
}

static int install_signal_handlers(struct server_ctx *ctx)
{
	struct sigaction sa = { .sa_handler = signal_handler };
	int ret;

	g_stop = &ctx->should_stop;
	ret = sigaction(SIGINT, &sa, NULL);
	if (ret)
		goto out_err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret)
		goto out_err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret)
		goto out_err;

	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret)
		goto out_err;

	return 0;

out_err:
	pr_error("Failed to install signal handlers: %s", strerror(errno));
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

/*
 * Guarding against the wrong file descriptor and logic errors.
 */
static int close_fd_p(int *fd)
{
	int tmp;

	if (unlikely(*fd < 0)) {
		pr_warn("Trying to close an invalid file descriptor: %d", *fd);
		return -EINVAL;
	}

	tmp = *fd;
	*fd = -1;
	return close(tmp);
}

static int init_socket_tcp(struct server_ctx *ctx)
{
	int fd, ret, family;
	socklen_t len;

	family = ctx->cfg.tcp_bind_addr.sa.sa_family;
	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ret = errno;
		pr_error("Failed to create TCP socket: %s", strerror(ret));
		return -ret;
	}

	if (family == AF_INET6)
		len = sizeof(ctx->cfg.tcp_bind_addr.in6);
	else
		len = sizeof(ctx->cfg.tcp_bind_addr.in4);

#ifdef SO_REUSEADDR
	ret = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ret, sizeof(ret));
#endif

	ret = bind(fd, &ctx->cfg.tcp_bind_addr.sa, len);
	if (ret) {
		ret = -errno;
		pr_error("Failed to bind TCP socket: %s", strerror(-ret));
		goto out_err;
	}

	ret = listen(fd, ctx->cfg.tcp_backlog);
	if (ret) {
		ret = -errno;
		pr_error("Failed to listen on TCP socket: %s", strerror(-ret));
		goto out_err;
	}

	pr_vinfo("Listening on TCP socket %s", sockaddr_to_str(&ctx->cfg.tcp_bind_addr));
	ctx->tcp_fd = fd;
	return 0;

out_err:
	close(fd);
	return ret;
}

static void free_socket_tcp(struct server_ctx *ctx)
{
	if (ctx->tcp_fd >= 0)
		close_fd_p(&ctx->tcp_fd);
}

static int init_socket_udp(struct server_ctx *ctx)
{
	int fd, ret, family;
	socklen_t len;

	family = ctx->cfg.udp_bind_addr.sa.sa_family;
	fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ret = -errno;
		pr_error("Failed to create UDP socket: %s", strerror(-ret));
		return -ret;
	}

	if (family == AF_INET6)
		len = sizeof(ctx->cfg.udp_bind_addr.in6);
	else
		len = sizeof(ctx->cfg.udp_bind_addr.in4);

	ret = bind(fd, &ctx->cfg.udp_bind_addr.sa, len);
	if (ret) {
		ret = -errno;
		pr_error("Failed to bind UDP socket: %s", strerror(-ret));
		goto out_err;
	}

	pr_vinfo("Listening on UDP socket %s", sockaddr_to_str(&ctx->cfg.udp_bind_addr));
	ctx->udp_fd = fd;
	return 0;

out_err:
	close(fd);
	return ret;
}

static void free_socket_udp(struct server_ctx *ctx)
{
	if (ctx->udp_fd >= 0)
		close_fd_p(&ctx->udp_fd);
}

static int init_socket(struct server_ctx *ctx)
{
	int ret;

	assert(ctx->cfg.using_tcp || ctx->cfg.using_udp);
	if (ctx->cfg.using_tcp) {
		ret = init_socket_tcp(ctx);
		if (ret)
			return ret;
	}

	if (ctx->cfg.using_udp) {
		ret = init_socket_udp(ctx);
		if (ret)
			goto out_err;
	}

	return 0;

out_err:
	free_socket_tcp(ctx);
	return ret;
}

static void free_socket(struct server_ctx *ctx)
{
	free_socket_tcp(ctx);
	free_socket_udp(ctx);
}

static int init_rate_limit(struct server_ctx *ctx)
{
	struct rate_limit *rl = &ctx->rl;
	struct token_bucket **tbuckets;
	int ret;

	rl->nr_tbuckets = 0;
	rl->nr_allocated = NR_INIT_BUCKETS;
	tbuckets = calloc(rl->nr_allocated, sizeof(*tbuckets));
	if (!tbuckets)
		return -ENOMEM;

	ret = pthread_mutex_init(&rl->lock, NULL);
	if (ret) {
		pr_error("Failed to initialize rate limit mutex: %s", strerror(ret));
		free(tbuckets);
		return -ret;
	}

	ret = ip_map_init(&rl->ip_map);
	if (ret) {
		pr_error("Failed to initialize IP map: %s", strerror(ret));
		free(tbuckets);
		pthread_mutex_destroy(&rl->lock);
		return ret;
	}

	rl->tbuckets = tbuckets;
	return 0;
}

static void free_rate_limit(struct server_ctx *ctx)
{
	struct rate_limit *rl = &ctx->rl;

	if (!rl->tbuckets)
		return;

	pthread_mutex_lock(&rl->lock);
	pthread_mutex_unlock(&rl->lock);
	free(rl->tbuckets);
	rl->tbuckets = NULL;
	rl->nr_allocated = 0;
	rl->nr_tbuckets = 0;
	pthread_mutex_destroy(&rl->lock);
	ip_map_destroy(&rl->ip_map);
}

static int send_event_fd(struct server_wrk *w)
{
	uint64_t val = 1;
	ssize_t ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_error("Failed to write to event FD: (ret = %zd): %s (thread %u)", ret, strerror(ret), w->idx);
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

static int epoll_add(struct server_wrk *w, int fd, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		ret = errno;
		pr_error("Failed to add FD %d to epoll: %s", fd, strerror(ret));
		abort();
	}

	return 0;
}

static int epoll_del(struct server_wrk *w, int fd)
{
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, fd, NULL);
	if (ret) {
		ret = errno;
		pr_error("Failed to delete FD %d from epoll: %s", fd, strerror(ret));
		abort();
	}

	return 0;
}

static int epoll_mod(struct server_wrk *w, int fd, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		ret = errno;
		pr_error("Failed to modify FD %d in epoll: %s\n", fd, strerror(ret));
		abort();
	}

	return 0;
}

static int init_epoll(struct server_wrk *w)
{
	int ep_fd = -1, ev_fd = -1, ret;
	union epoll_data data;

	ep_fd = epoll_create(64);
	if (ep_fd < 0) {
		ret = -errno;
		pr_error("Failed to create epoll FD: %s", strerror(-ret));
		return ret;
	}

	ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ev_fd < 0) {
		ret = -errno;
		pr_error("Failed to create event FD: %s", strerror(-ret));
		goto out_err;
	}

	w->ep_fd = ep_fd;
	w->ev_fd = ev_fd;
	data.u64 = EPL_DT_EVENT_FD;
	ret = epoll_add(w, ev_fd, EPOLLIN, data);
	if (ret) {
		w->ep_fd = -1;
		w->ev_fd = -1;
		goto out_err;
	}

	return 0;

out_err:
	if (ep_fd >= 0)
		close_fd_p(&ep_fd);
	if (ev_fd >= 0)
		close_fd_p(&ev_fd);

	return ret;
}

static void free_epoll(struct server_wrk *w)
{
	if (w->ep_fd >= 0)
		close_fd_p(&w->ep_fd);

	if (w->ev_fd >= 0)
		close_fd_p(&w->ev_fd);
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
	uint32_t i, n = w->nr_clients;
	size_t size;
	int ret;

	size = sizeof(*cl_stack) + (sizeof(*cl_stack->data) * n);
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
	cl_stack->bp = n;
	for (i = n; i > 0; i--)
		__push_client_stack(cl_stack, i - 1);

	w->cl_stack = cl_stack;
	return 0;
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

static void init_client(struct client_state *c)
{
	c->client_fd = -1;
	c->target_fd = -1;
	c->cpoll_mask = 0;
	c->tpoll_mask = 0;
	/* c->idx is intact. */
	c->cbuf_len = 0;
	c->tbuf_len = 0;
	c->cbuf = NULL;
	c->tbuf = NULL;
	memset(&c->client_addr, 0, sizeof(c->client_addr));
	c->tbucket = NULL;
	c->is_rate_limited = false;
}

static int init_clients(struct server_wrk *w)
{
	struct client_state *clients;
	uint32_t i, n = NR_CLIENTS;
	int ret;

	clients = calloc(n, sizeof(*clients));
	if (!clients) {
		pr_error("Failed to allocate memory for clients");
		return -ENOMEM;
	}

	for (i = 0; i < n; i++) {
		struct client_state *c = &clients[i];

		init_client(c);
		c->idx = i;
	}

	w->nr_clients = n;
	w->clients = clients;

	ret = init_client_stack(w);
	if (ret) {
		w->nr_clients = 0;
		w->clients = NULL;
		free(clients);
		return ret;
	}

	return 0;
}

static void free_clients(struct server_wrk *w)
{
	uint32_t i, tmp;

	if (!w->clients)
		return;

	for (i = 0; i < w->nr_clients; i++) {
		struct client_state *c = &w->clients[i];

		if (c->client_fd >= 0)
			close_fd_p(&c->client_fd);

		if (c->target_fd >= 0)
			close_fd_p(&c->target_fd);

		if (c->cbuf)
			free(c->cbuf);

		if (c->tbuf)
			free(c->tbuf);

		if (c->tbucket) {
			pthread_mutex_lock(&c->tbucket->lock);
			tmp = c->tbucket->ref_cnt--;
			pthread_mutex_unlock(&c->tbucket->lock);
			if (tmp == 1)
				free(c->tbucket);
		}
	}

	free_client_stack(w);
	free(w->clients);
	w->clients = NULL;
	w->nr_clients = 0;
}

static void *server_worker_thread(void *warg);

static int init_worker(struct server_ctx *ctx, struct server_wrk *w)
{
	int ret;

	ret = init_epoll(w);
	if (ret)
		return ret;

	ret = init_clients(w);
	if (ret) {
		free_epoll(w);
		return ret;
	}

	w->ctx = ctx;
	if (w->idx > 0) {
		pr_vinfo("Starting sub worker %u", w->idx);
		ret = pthread_create(&w->thread, NULL, server_worker_thread, w);
		if (ret) {
			pr_error("Failed to create worker thread: %s", strerror(ret));
			free_clients(w);
			free_epoll(w);
			w->ctx = NULL;
			return -ret;
		}
	}

	return 0;
}

static void free_worker(struct server_wrk *w)
{
	if (!w->ctx)
		return;

	if (w->idx > 0) {
		pr_vinfo("Stopping sub worker %u", w->idx);
		send_event_fd(w);
		pthread_join(w->thread, NULL);
		pr_vinfo("Sub worker %u stopped", w->idx);
	}

	free_epoll(w);
}

static int init_workers(struct server_ctx *ctx)
{
	struct server_wrk *workers;
	uint32_t i;
	int ret;

	assert(ctx->cfg.nr_workers > 0);

	workers = calloc(ctx->cfg.nr_workers, sizeof(*workers));
	if (!workers) {
		pr_error("Failed to allocate memory for workers");
		return -ENOMEM;
	}

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		workers[i].ep_fd = -1;
		workers[i].ev_fd = -1;
	}

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct server_wrk *w = &workers[i];

		w->idx = i;
		w->ctx = NULL;
		w->ep_timeout = 5000;
		w->cl_stack = NULL;
		w->clients = NULL;
		w->nr_clients = 0;
		w->nr_active_clients = 0;
		w->handle_events_should_break = false;

		ret = init_worker(ctx, w);
		if (ret)
			goto out_err;
	}

	ctx->workers = workers;
	return 0;

out_err:
	while (i--)
		free_worker(&workers[i]);

	free(workers);
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

static int propagate_workers(struct server_ctx *ctx)
{
	union epoll_data data;
	struct server_wrk *w;
	int ret;

	if (ctx->cfg.using_tcp) {
		w = &ctx->workers[0];
		data.u64 = EPL_DT_TCP_FD;
		ret = epoll_add(w, ctx->tcp_fd, EPOLLIN, data);
		if (ret)
			return ret;
	}

	if (ctx->cfg.using_udp) {
		w = &ctx->workers[0];
		if (ctx->nr_workers > 1)
			w = &ctx->workers[1];

		data.u64 = EPL_DT_UDP_FD;
		ret = epoll_add(w, ctx->udp_fd, EPOLLIN, data);
		if (ret)
			return ret;
	}

	return 0;
}

static int init_server_ctx(struct server_ctx *ctx)
{
	int ret;

	set_default_server_ctx(ctx);
	try_increase_rlimit_nofile();

	g_verbose = ctx->cfg.verbose;
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ret = init_socket(ctx);
	if (ret)
		return ret;

	ret = init_rate_limit(ctx);
	if (ret) {
		free_socket(ctx);
		return ret;
	}

	ret = init_workers(ctx);
	if (ret) {
		free_socket(ctx);
		free_rate_limit(ctx);
		return ret;
	}

	ret = propagate_workers(ctx);
	if (ret) {
		free_workers(ctx);
		free_socket(ctx);
		free_rate_limit(ctx);
		return ret;
	}

	return 0;
}

static struct server_wrk *pick_worker_for_new_conn(struct server_ctx *ctx,
						   struct sockaddr_in46 *taddr)
{
	struct server_wrk *w = NULL;
	uint32_t i, min;

	pr_debug("Picking a new worker for new connection to %s", sockaddr_to_str(taddr));

	w = &ctx->workers[0];
	min = atomic_load(&ctx->workers[0].nr_active_clients);
	for (i = 1; i < ctx->cfg.nr_workers; i++) {
		uint32_t nr;

		nr = atomic_load(&ctx->workers[i].nr_active_clients);
		if (nr < min) {
			min = nr;
			w = &ctx->workers[i];
		}
	}

	return w;
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
	assert(c->client_fd < 0);
	assert(c->target_fd < 0);
	assert(c->idx == idx);

	atomic_fetch_add(&w->nr_active_clients, 1u);
	return c;
}

static void rearm_tcp_accept(struct server_ctx *ctx)
{
	union epoll_data data;
	int ret;

	if (!ctx->accept_need_rearm)
		return;

	data.u64 = EPL_DT_TCP_FD;
	ret = epoll_mod(&ctx->workers[0], ctx->tcp_fd, EPOLLIN, data);
	if (ret) {
		pr_error("Failed to rearm accept: %s", strerror(ret));
		ctx->should_stop = true;
		send_event_fd(&ctx->workers[0]);
	}

	ctx->accept_need_rearm = false;
}

static void put_client_slot(struct server_wrk *w, struct client_state *c)
{
	bool handle_events_should_break = false;
	int ret, tmp;

	if (c->cbuf) {
		free(c->cbuf);
		c->cbuf = NULL;
		c->cbuf_len = 0;
	} else {
		assert(c->cbuf_len == 0);
	}

	if (c->tbuf) {
		free(c->tbuf);
		c->tbuf = NULL;
		c->tbuf_len = 0;
	} else {
		assert(c->tbuf_len == 0);
	}

	if (c->client_fd >= 0) {
		pr_vinfo("Closing a client connection (src=%s, thread=%u)",
			 sockaddr_to_str(&c->client_addr), w->idx);

		tmp = -c->client_fd;
		ret = epoll_del(w, c->client_fd);
		assert(!ret);
		close_fd_p(&c->client_fd);
		c->client_fd = tmp;
		handle_events_should_break = true;
	}

	if (c->target_fd >= 0) {
		tmp = -c->target_fd;
		ret = epoll_del(w, c->target_fd);
		assert(!ret);
		close_fd_p(&c->target_fd);
		c->target_fd = tmp;
		handle_events_should_break = true;
	}

	if (unlikely(handle_events_should_break && w->ctx->accept_need_rearm))
		rearm_tcp_accept(w->ctx);

	c->is_rate_limited = false;
	w->handle_events_should_break = handle_events_should_break;
	atomic_fetch_sub(&w->nr_active_clients, 1u);
	memset(&c->client_addr, 0, sizeof(c->client_addr));
	ret = push_client_stack(w->cl_stack, c->idx);
	assert(!ret);
	(void)ret;
}

static int tcp_get_original_dst(int fd, struct sockaddr_in46 *orig_addr, socklen_t *len)
{
	int ret;

	ret = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &orig_addr->sa, len);
	if (ret)
		return -errno;

	return 0;
}

static int prepare_tcp_target_connect(struct server_wrk *w, struct client_state *c)
{
	struct sockaddr_in46 taddr = w->ctx->cfg.tcp_target_addr;
	bool run_tproxy = false;
	union epoll_data data;
	int fd, ret, family;
	socklen_t len;

	family = taddr.sa.sa_family;
	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ret = errno;
		pr_error("Failed to create target socket: %s", strerror(ret));
		return -ret;
	}

#ifdef TCP_NODELAY
	ret = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret));
#endif

	ret = 0;
	if (family == AF_INET6) {
		len = sizeof(taddr.in6);
		if (memcmp(&taddr.in6.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0) {
			ret = tcp_get_original_dst(c->client_fd, &taddr, &len);
			run_tproxy = true;
		}
	} else {
		len = sizeof(taddr.in4);
		if (taddr.in4.sin_addr.s_addr == INADDR_ANY) {
			ret = tcp_get_original_dst(c->client_fd, &taddr, &len);
			run_tproxy = true;
		}
	}

	if (ret) {
		pr_error("Failed to get original destination: %s", strerror(-ret));
		close_fd_p(&fd);
		return ret;
	}

	if (run_tproxy)
		pr_debug("Running TPROXY on %s to %s", sockaddr_to_str(&c->client_addr), sockaddr_to_str(&taddr));
	else
		pr_debug("Connecting proxy from %s to %s", sockaddr_to_str(&c->client_addr), sockaddr_to_str(&taddr));

	ret = connect(fd, &taddr.sa, len);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			pr_error("Failed to connect to target: %s", strerror(ret));
			close_fd_p(&fd);
			return -ret;
		}
	}

	c->target_fd = fd;

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
	c->cpoll_mask = 0;
	ret = epoll_add(w, c->client_fd, c->cpoll_mask, data);
	if (ret) {
		pr_error("Failed to add target FD to epoll: %s", strerror(ret));
		close_fd_p(&fd);
		return ret;
	}

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_TARGET_TCP_CONNECT;
	c->tpoll_mask = EPOLLOUT | EPOLLIN;
	ret = epoll_add(w, c->target_fd, c->tpoll_mask, data);
	if (ret) {
		pr_error("Failed to add target FD to epoll: %s", strerror(ret));
		close_fd_p(&fd);
		return ret;
	}

	send_event_fd(w);
	return 0;
}

static int register_new_tcp_client(struct server_ctx *ctx, int fd,
				   struct sockaddr_in46 *addr)
{
	struct client_state *c;
	struct server_wrk *w;
	int ret;

	w = pick_worker_for_new_conn(ctx, addr);
	c = get_free_client_slot(w);
	if (unlikely(!c)) {
		pr_error("Failed to get a free client slot on worker %u", w->idx);
		return -EAGAIN;
	}

	pr_debug("Registering new TCP client %s (fd=%d) on worker %u", sockaddr_to_str(addr), fd, w->idx);
	c->client_fd = fd;
	c->client_addr = *addr;

	ret = prepare_tcp_target_connect(w, c);
	if (ret) {
		put_client_slot(w, c);
		pr_error("Failed to prepare TCP target connect: %s", strerror(ret));
		return ret;
	}

	return 0;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		w->ctx->accept_need_rearm = true;
		return epoll_del(w, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static int handle_event_tcp_accept(struct server_wrk *w)
{
	struct server_ctx *ctx = w->ctx;
	struct sockaddr_in46 addr;
	socklen_t len;
	int ret, fd;

	memset(&addr, 0, sizeof(addr));
	if (ctx->cfg.tcp_bind_addr.sa.sa_family == AF_INET6)
		len = sizeof(addr.in6);
	else
		len = sizeof(addr.in4);

	ret = accept(ctx->tcp_fd, &addr.sa, &len);
	if (unlikely(ret < 0))
		return handle_accept_error(errno, w);

	fd = ret;
	if (unlikely(len > (socklen_t)sizeof(addr))) {
		pr_error("accept() returned invalid address length: %u", len);
		close(ret);
		return -EINVAL;
	}

	ret = set_fd_nonblock(fd);
	if (ret) {
		pr_error("Failed to set client FD non-blocking: %s", strerror(ret));
		close_fd_p(&ret);
		return ret;
	}

	pr_vinfo("New connection from %s", sockaddr_to_str(&addr));

	ret = register_new_tcp_client(ctx, fd, &addr);
	if (ret) {
		pr_error("Failed to give client FD to a worker: %s", strerror(ret));
		close_fd_p(&fd);

		/* Yes, it's "return 0;", don't exit on fail... */
		return 0;
	}

	return 0;
}

static int handle_event_tcp_fd(struct server_wrk *w, struct epoll_event *ev)
{
	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP))) {
		pr_error("TCP FD error, hit {EPOLLERR | EPOLLHUP}: 0x%x", ev->events);
		return -EIO;
	}

	if (likely(ev->events & EPOLLIN))
		return handle_event_tcp_accept(w);

	pr_warn("Unexpected event on TCP FD: 0x%x", ev->events);
	return 0;
}

static int handle_event_udp_fd(struct server_wrk *w, struct epoll_event *ev)
{
	return 0;
}

static int handle_event_event_fd(struct server_wrk *w, struct epoll_event *ev)
{
	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP))) {
		pr_error("Event FD error, hit {EPOLLERR | EPOLLHUP}: 0x%x", ev->events);
		return -EIO;
	}

	if (likely(ev->events & EPOLLIN))
		return consume_event_fd(w);

	pr_warn("Unexpected event on event FD: 0x%x", ev->events);
	return 0;
}

static int handle_event_tcp_target_connect(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	struct sockaddr_in46 target_addr;
	uint32_t events = ev->events;
	union epoll_data data;
	socklen_t len;
	int ret, tmp;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_error("Target connect failed, hit {EPOLLERR | EPOLLHUP}: 0x%x (thread %u)", events, w->idx);
		put_client_slot(w, c);
		return 0;
	}

	tmp = 0;
	len = sizeof(tmp);
	ret = getsockopt(c->target_fd, SOL_SOCKET, SO_ERROR, &tmp, &len);
	if (unlikely(tmp || !(events & EPOLLOUT))) {
		if (tmp < 0)
			tmp = -tmp;
		pr_error("Failed to get target socket error: %s (thread %u)", strerror(tmp), w->idx);
		put_client_slot(w, c);
		return 0;
	}

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
	c->tpoll_mask = EPOLLIN;
	ret = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
	c->cpoll_mask = EPOLLIN;
	ret = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	c->cbuf_len = 0;
	c->tbuf_len = 0;
	c->cbuf = malloc(SPLICE_BUF_SIZE);
	c->tbuf = malloc(SPLICE_BUF_SIZE);
	if (unlikely(!c->cbuf || !c->tbuf)) {
		pr_error("Failed to allocate splice buffers: %s (thread %u)", strerror(errno), w->idx);
		put_client_slot(w, c);
		return -ENOMEM;
	}

	if (c->client_addr.sa.sa_family == AF_INET6)
		len = sizeof(c->client_addr.in6);
	else
		len = sizeof(c->client_addr.in4);

	memset(&target_addr, 0, sizeof(target_addr));
	getpeername(c->target_fd, &target_addr.sa, &len);

	pr_debug("Forwarding connection from %s to %s has been established (thread %u)",
		 sockaddr_to_str(&c->client_addr), sockaddr_to_str(&target_addr), w->idx);
	return 0;
}

struct tcp_splice_buf {
	char *buf;
	size_t cur_len;
	size_t max_len;
	size_t max_recv;
	size_t max_send;
};

static ssize_t do_tcp_splice(int src_fd, int dst_fd, struct tcp_splice_buf *sb)
{
	size_t recv_len;
	size_t send_len;
	ssize_t ret = 0;

	recv_len = sb->max_len - sb->cur_len;
	if (recv_len > sb->max_recv)
		recv_len = sb->max_recv;

	if (recv_len > 0) {
		ret = recv(src_fd, sb->buf + sb->cur_len, recv_len, MSG_DONTWAIT);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN)
				goto do_send;

			pr_verror("Failed to read from FD %d: %s", src_fd, strerror(ret));
			return -ret;
		}

		if (ret == 0)
			return -EIO;

		sb->cur_len += (size_t)ret;
	}

do_send:
	if (sb->cur_len == 0)
		return 0;

	send_len = sb->cur_len;
	if (send_len > sb->max_send)
		send_len = sb->max_send;

	if (send_len > 0) {
		ret = send(dst_fd, sb->buf, send_len, MSG_DONTWAIT);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN)
				return 0;

			pr_verror("Failed to write to FD %d: %s", dst_fd, strerror(ret));
			return -ret;
		}

		if (ret == 0)
			return -EIO;

		sb->cur_len -= (size_t)ret;
		if (sb->cur_len > 0)
			memmove(sb->buf, sb->buf + ret, sb->cur_len);
	}

	return ret;
}

static int handle_event_tcp_target_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	uint32_t events = ev->events;
	struct tcp_splice_buf sb;
	union epoll_data data;
	ssize_t ret;
	int err;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		sb.buf = c->tbuf;
		sb.cur_len = c->tbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		sb.max_recv = sb.max_len;
		sb.max_send = sb.max_len;
		ret = do_tcp_splice(c->target_fd, c->client_fd, &sb);
		if (unlikely(ret < 0)) {
			put_client_slot(w, c);
			return 0;
		}

		c->tbuf_len = sb.cur_len;
		if (c->tbuf_len > 0) {
			/*
			 * Client is not ready to receive more data, so we
			 * need to wait for EPOLLOUT.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
			c->cpoll_mask |= EPOLLOUT;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}

		if (c->tbuf_len == SPLICE_BUF_SIZE) {
			/*
			 * Target buffer is full, stop reading from target
			 * until we have more space.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
			c->tpoll_mask &= ~EPOLLIN;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}
	}

	if (events & EPOLLOUT) {
		sb.buf = c->cbuf;
		sb.cur_len = c->cbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		sb.max_recv = sb.max_len;
		sb.max_send = sb.max_len;
		ret = do_tcp_splice(c->client_fd, c->target_fd, &sb);
		if (unlikely(ret < 0)) {
			put_client_slot(w, c);
			return 0;
		}

		c->cbuf_len = sb.cur_len;
		if (c->cbuf_len == 0) {
			/*
			 * Buffer is fully flushed to the target, stop
			 * the EPOLLOUT event.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
			c->tpoll_mask &= ~EPOLLOUT;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}

		if (c->cbuf_len < SPLICE_BUF_SIZE && !(c->cpoll_mask & EPOLLIN)) {
			/*
			 * Client is ready to receive more data, start
			 * reading from client again.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
			c->cpoll_mask |= EPOLLIN;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}
	}

	return 0;
}

static int handle_event_tcp_client_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	uint32_t events = ev->events;
	struct tcp_splice_buf sb;
	union epoll_data data;
	ssize_t ret;
	int err;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		sb.buf = c->cbuf;
		sb.cur_len = c->cbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		sb.max_recv = sb.max_len;
		sb.max_send = sb.max_len;
		ret = do_tcp_splice(c->client_fd, c->target_fd, &sb);
		if (unlikely(ret < 0)) {
			put_client_slot(w, c);
			return 0;
		}

		c->cbuf_len = sb.cur_len;
		if (c->cbuf_len > 0) {
			/*
			 * Target is not ready to receive more data, so we
			 * need to wait for EPOLLOUT.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
			c->tpoll_mask |= EPOLLOUT;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}

		if (c->cbuf_len == SPLICE_BUF_SIZE) {
			/*
			 * Client buffer is full, stop reading from client
			 * until we have more space.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
			c->cpoll_mask &= ~EPOLLIN;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}
	}

	if (events & EPOLLOUT) {
		sb.buf = c->tbuf;
		sb.cur_len = c->tbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		sb.max_recv = sb.max_len;
		sb.max_send = sb.max_len;
		ret = do_tcp_splice(c->target_fd, c->client_fd, &sb);
		if (unlikely(ret < 0)) {
			put_client_slot(w, c);
			return 0;
		}

		c->tbuf_len = sb.cur_len;
		if (c->tbuf_len == 0) {
			/*
			 * Buffer is fully flushed to the client, stop
			 * the EPOLLOUT event.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
			c->cpoll_mask &= ~EPOLLOUT;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}

		if (c->tbuf_len < SPLICE_BUF_SIZE && !(c->tpoll_mask & EPOLLIN)) {
			/*
			 * Target is ready to receive more data, start
			 * reading from target again.
			 */
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
			c->tpoll_mask |= EPOLLIN;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}
	}

	return 0;
}

static int poll_events(struct server_wrk *w)
{
	int ret;

	w->handle_events_should_break = false;
	ret = epoll_wait(w->ep_fd, w->events, NR_EPOLL_EVENTS, w->ep_timeout);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EINTR)
			return 0;

		pr_error("epoll_wait() failed: %s", strerror(ret));
		return -ret;
	}

	return ret;
}

static int handle_event(struct server_wrk *w, struct epoll_event *ev)
{
	uint64_t mask;

	switch (ev->data.u64) {
	case EPL_DT_TCP_FD:
		return handle_event_tcp_fd(w, ev);
	case EPL_DT_UDP_FD:
		return handle_event_udp_fd(w, ev);
	case EPL_DT_EVENT_FD:
		return handle_event_event_fd(w, ev);
	}

	mask = ev->data.u64 & EPL_DT_MASK_CLIENT_TCP_DATA;
	ev->data.u64 &= ~EPL_DT_MASK_CLIENT_TCP_DATA;

	switch (mask) {
	case EPL_DT_MASK_CLIENT_TCP_DATA:
		return handle_event_tcp_client_data(w, ev);
	case EPL_DT_MASK_TARGET_TCP_CONNECT:
		return handle_event_tcp_target_connect(w, ev);
	case EPL_DT_MASK_TARGET_TCP_DATA:
		return handle_event_tcp_target_data(w, ev);
	case EPL_DT_MASK_CLIENT_UDP_DATA:
		return 0;
	case EPL_DT_MASK_TARGET_UDP_DATA:
		return 0;
	}

	pr_warn("Unknown event data: 0x%lx (mask: 0x%lx)", ev->data.u64, mask);
	return 0;
}

static int handle_events(struct server_wrk *w, int n)
{
	int ret = 0, i;

	for (i = 0; i < n; i++) {
		ret = handle_event(w, &w->events[i]);
		if (ret < 0)
			break;

		if (w->handle_events_should_break)
			break;
	}

	return ret;
}

static void *server_worker_thread(void *warg)
{
	struct server_wrk *w = warg;
	struct server_ctx *ctx = w->ctx;
	int ret = 0;

	if (w->idx == 0)
		pr_vinfo("The main worker is ready! (worker 0)");

	while (!ctx->should_stop) {
		ret = poll_events(w);
		if (ret < 0)
			break;

		ret = handle_events(w, ret);
		if (ret < 0)
			break;
	}

	return (void *)(long)ret;
}

static int run_server(struct server_ctx *ctx)
{
	void *ret_p;
	long ret;

	ret_p = server_worker_thread(&ctx->workers[0]);
	ret = (long)ret_p;

	return (int)ret;
}

static void free_server_ctx(struct server_ctx *ctx)
{
	ctx->should_stop = true;
	free_workers(ctx);
	free_socket(ctx);
	free_rate_limit(ctx);
}

int main(int argc, char *argv[])
{
	struct server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	set_default_server_cfg(&ctx.cfg);

	ret = parse_args(argc, argv, &ctx.cfg);
	if (ret < 0) {
		show_help(argv[0]);
		goto out;
	}

	ret = init_server_ctx(&ctx);
	if (ret)
		goto out;

	ret = run_server(&ctx);
	free_server_ctx(&ctx);
out:
	return (ret < 0) ? -ret : ret;
}
