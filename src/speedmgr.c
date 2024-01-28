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

#ifndef __must_hold
#define __must_hold(x)
#endif

#ifndef __acquires
#define __acquires(x)
#endif

#ifndef __releases
#define __releases(x)
#endif

#define SPEEDMGR_DEBUG		0
#define NR_CLIENTS		20480
#define NR_INIT_BUCKETS		4
#define SPLICE_BUF_SIZE		8192

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST		80
#endif

#if SPEEDMGR_DEBUG
#define pr_debug(fmt, ...) printf("[%08d][D]: " fmt "\n", gettid(), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do {} while (0)
#endif

#define pr_info(fmt, ...)	printf("[%08d][I]: " fmt "\n", gettid(), ##__VA_ARGS__)
#define pr_error(fmt, ...)	printf("[%08d][E]: " fmt "\n", gettid(), ##__VA_ARGS__)
#define pr_warn(fmt, ...)	printf("[%08d][w]: " fmt "\n", gettid(), ##__VA_ARGS__)
#define pr_vinfo(fmt, ...)	do { if (g_verbose) pr_info(fmt, ##__VA_ARGS__); } while (0)
#define pr_verror(fmt, ...)	do { if (g_verbose) pr_error(fmt, ##__VA_ARGS__); } while (0)
#define pr_vwarn(fmt, ...)	do { if (g_verbose) pr_warn(fmt, ##__VA_ARGS__); } while (0)
#define pr_vdebug(fmt, ...)	do { if (g_verbose) pr_debug(fmt, ##__VA_ARGS__); } while (0)

#define NR_EPOLL_EVENTS		128

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
	/* Family is 4 or 6 (not using AF_INET/AF_INET6.)*/
	char family;
	union {
		struct in_addr in4;
		struct in6_addr in6;
	};
};

struct client_state;

struct token_bucket {
	pthread_mutex_t		lock;
	int			timer_fd;
	_Atomic(int64_t)	upload_tokens;
	_Atomic(int64_t)	download_tokens;
	int64_t			max_upload_tokens;
	int64_t			max_download_tokens;
	_Atomic(uint32_t)	nr_up_rate_limted;
	_Atomic(uint32_t)	nr_down_rate_limted;
	uint32_t		ref_cnt;	/* Protected by lock. */
	_Atomic(uint32_t)	nr_clients;	/* Protected by lock. */
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

struct server_wrk;

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
	struct sockaddr_in46	target_addr;
	struct token_bucket	*tbucket;
	struct server_wrk	*wrk_ref;
	volatile bool		is_up_rate_limited;
	volatile bool		is_down_rate_limited;
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
	bool			run_as_tproxy_tcp;
	bool			run_as_tproxy_udp;
	int			tcp_backlog;
	uint32_t		nr_workers;
	int64_t			max_upload_speed;
	int64_t			max_download_speed;
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


static inline socklen_t get_sockaddr_len(struct sockaddr_in46 *addr)
{
	if (addr->sa.sa_family == AF_INET6)
		return sizeof(addr->in6);
	else
		return sizeof(addr->in4);
}

static bool is_addr_any(struct sockaddr_in46 *addr)
{
	if (addr->sa.sa_family == AF_INET6) {
		if (memcmp(&addr->in6.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0)
			return true;
	} else {
		if (addr->in4.sin_addr.s_addr == INADDR_ANY)
			return true;
	}

	return false;
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
	cfg->using_tcp = false;
	cfg->using_udp = false;
	cfg->run_as_tproxy_tcp = false;
	cfg->run_as_tproxy_udp = false;
	cfg->tcp_backlog = 128;
	cfg->nr_workers = 1;
	cfg->max_upload_speed = 0;
	cfg->max_download_speed = 0;
	cfg->interval_ms = 0;
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
			cfg->max_download_speed = (int64_t)atoll(optarg);
			p.got_max_download_speed = true;
			break;

		case 'd':
			cfg->max_upload_speed = (int64_t)atoll(optarg);
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

		cfg->run_as_tproxy_tcp = is_addr_any(&cfg->tcp_target_addr);
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

		cfg->run_as_tproxy_udp = is_addr_any(&cfg->udp_target_addr);
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

static const char *addr_to_str(const struct in46_addr *addr)
{
	static __thread char __buf[8][INET6_ADDRSTRLEN + sizeof("[]")];
	static __thread uint8_t __idx;
	char *buf = __buf[__idx++ % 8];

	if (addr->family == 4) {
		inet_ntop(AF_INET, &addr->in4, buf, INET_ADDRSTRLEN);
	} else {
		*buf = '[';
		inet_ntop(AF_INET6, &addr->in6, buf + 1, INET6_ADDRSTRLEN);
		strcat(buf, "]");
	}

	return buf;
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

#ifdef TCP_NODELAY
	ret = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret));
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

static int epoll_add(struct server_wrk *w, int fd, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, fd, &ev);
	if (unlikely(ret)) {
		ret = errno;
		pr_error("Failed to add FD %d to epoll (epl_fd=%d): %s (thread=%u)",
			 fd, w->ep_fd, strerror(ret), w->idx);
		return -ret;
	}

	return 0;
}

static int epoll_del(struct server_wrk *w, int fd)
{
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, fd, NULL);
	if (ret) {
		ret = errno;
		pr_error("Failed to delete FD %d from epoll (epl_fd=%d): %s (thread=%u)",
			 fd, w->ep_fd, strerror(ret), w->idx);
		return -ret;
	
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
		pr_error("Failed to modify FD %d in epoll (epl_fd=%d): %s (thread=%u)",
			 fd, w->ep_fd, strerror(ret), w->idx);
		return -ret;
	
	}

	return 0;
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

static struct token_bucket *__find_token_bucket(struct rate_limit *rl,
						const struct in46_addr *addr)
	__must_hold(&rl->lock)
{
	int family = addr->family;
	struct token_bucket *tb;
	const void *key;
	int ret;

	if (family == 4)
		key = &addr->in4;
	else
		key = &addr->in6;

	ret = ip_map_get(&rl->ip_map, key, family, (void **)&tb);
	if (ret == 0)
		return tb;

	if (unlikely(ret != -ENOENT))
		pr_error("Failed to get token bucket from IP map: %s", strerror(-ret));

	return NULL;
}

static int add_token_bucket_to_rl(struct rate_limit *rl, struct token_bucket *tb)
	__must_hold(&rl->lock)
{
	const struct in46_addr *addr = &tb->addr;
	uint32_t nr_allocated, nr_tbuckets;
	struct token_bucket **tbuckets;
	const void *ip_key;
	int ret;

	if (addr->family == 4)
		ip_key = &addr->in4;
	else
		ip_key = &addr->in6;

	ret = ip_map_add(&rl->ip_map, ip_key, addr->family, tb);
	if (unlikely(ret))
		return ret;

	nr_allocated = rl->nr_allocated;
	nr_tbuckets = rl->nr_tbuckets;
	if (nr_tbuckets == nr_allocated) {
		nr_allocated *= 2;
		tbuckets = realloc(rl->tbuckets, sizeof(*tbuckets) * nr_allocated);
		if (!tbuckets) {
			pr_error("Failed to reallocate memory for token buckets");
			ip_map_del(&rl->ip_map, ip_key, addr->family);
			return -ENOMEM;
		}

		rl->tbuckets = tbuckets;
		rl->nr_allocated = nr_allocated;
	}

	rl->tbuckets[nr_tbuckets++] = tb;
	rl->nr_tbuckets = nr_tbuckets;
	return 0;
}

static int del_token_bucket_from_rl(struct rate_limit *rl, struct token_bucket *tb)
	__must_hold(&rl->lock)
	__must_hold(&tb->lock)
{
	const struct in46_addr *addr = &tb->addr;
	uint32_t nr_tbuckets, i;
	const void *ip_key;
	int ret;

	nr_tbuckets = rl->nr_tbuckets;
	for (i = 0; i < nr_tbuckets; i++) {
		if (rl->tbuckets[i] == tb)
			break;
	}

	if (i == nr_tbuckets) {
		pr_error("Token bucket not found in rate limit");
		return -ENOENT;
	}

	if (i != nr_tbuckets - 1)
		rl->tbuckets[i] = rl->tbuckets[nr_tbuckets - 1];

	nr_tbuckets--;
	rl->nr_tbuckets = nr_tbuckets;

	if (addr->family == 4)
		ip_key = &addr->in4;
	else
		ip_key = &addr->in6;

	ret = ip_map_del(&rl->ip_map, ip_key, addr->family);
	if (unlikely(ret))
		pr_error("Failed to delete token bucket from IP map: %s", strerror(-ret));

	return 0;
}

static inline void ms_to_timespec(uint64_t ms, struct timespec *ts)
{
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000000;
}

static int start_token_bucket_timer(struct server_ctx *ctx, struct token_bucket *tb)
	__must_hold(&ctx->rl.lock)
	__must_hold(&tb->lock)
{
	union epoll_data data;
	struct itimerspec its;
	int ret, timer_fd;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timer_fd < 0) {
		ret = errno;
		pr_error("Failed to create timer FD: %s", strerror(ret));
		return -ret;
	}

	ms_to_timespec(ctx->cfg.interval_ms, &its.it_interval);
	its.it_value = its.it_interval;
	ret = timerfd_settime(timer_fd, 0, &its, NULL);
	if (ret) {
		ret = errno;
		pr_error("Failed to set timer FD: %s", strerror(ret));
		close_fd_p(&timer_fd);
		return -ret;
	}

	tb->timer_fd = timer_fd;
	data.u64 = 0;
	data.ptr = tb;
	data.u64 |= EPL_DT_MASK_TIMER;
	ret = epoll_add(&ctx->workers[0], timer_fd, EPOLLIN, data);
	if (ret) {
		pr_error("Failed to add timer FD to epoll: %s", strerror(-ret));
		close_fd_p(&timer_fd);
		return ret;
	}

	tb->max_upload_tokens = ctx->cfg.max_upload_speed;
	tb->max_download_tokens = ctx->cfg.max_download_speed;
	atomic_store(&tb->upload_tokens, tb->max_upload_tokens);
	atomic_store(&tb->download_tokens, tb->max_download_tokens);
	return 0;
}

static struct token_bucket *create_token_bucket(struct server_ctx *ctx,
						const struct in46_addr *addr)
	__must_hold(&ctx->rl.lock)
{
	struct token_bucket *tb;
	int ret;

	pr_vdebug("Creating token bucket for %s", addr_to_str(addr));
	tb = calloc(1, sizeof(*tb));
	if (!tb) {
		pr_error("Failed to allocate memory for token bucket");
		return NULL;
	}

	ret = pthread_mutex_init(&tb->lock, NULL);
	if (ret) {
		pr_error("Failed to initialize token bucket mutex: %s", strerror(ret));
		free(tb);
		return NULL;
	}

	pthread_mutex_lock(&tb->lock);
	ret = start_token_bucket_timer(ctx, tb);
	if (unlikely(ret)) {
		pr_error("Failed to start token bucket timer: %s", strerror(-ret));
		pthread_mutex_unlock(&tb->lock);
		pthread_mutex_destroy(&tb->lock);
		free(tb);
		return NULL;
	}

	tb->addr = *addr;
	tb->clients = NULL;
	tb->nr_clients = 0;
	tb->ref_cnt = 1;
	pthread_mutex_unlock(&tb->lock);

	ret = add_token_bucket_to_rl(&ctx->rl, tb);
	if (unlikely(ret)) {
		pr_error("Failed to add token bucket to rate limit: %s", strerror(-ret));
		pthread_mutex_destroy(&tb->lock);
		free(tb);
		return NULL;
	}

	return tb;
}

static int add_client_to_tbucket(struct token_bucket *tb, struct client_state *c)
	__must_hold(&tb->lock)
{
	struct client_state **clients;
	uint32_t nr_clients;

	nr_clients = tb->nr_clients + 1;
	clients = realloc(tb->clients, sizeof(*clients) * nr_clients);
	if (!clients) {
		pr_error("Failed to reallocate memory for clients");
		return -ENOMEM;
	}

	tb->clients = clients;
	tb->clients[tb->nr_clients++] = c;
	return 0;
}

static int del_client_from_tbucket(struct token_bucket *tb, struct client_state *c)
	__must_hold(&tb->lock)
{
	struct client_state **clients;
	uint32_t nr_clients, i;

	nr_clients = tb->nr_clients;
	clients = tb->clients;
	for (i = 0; i < nr_clients; i++) {
		if (clients[i] == c)
			break;
	}

	if (i == nr_clients) {
		pr_error("Client not found in token bucket");
		return -ENOENT;
	}

	if (i != nr_clients - 1)
		clients[i] = clients[nr_clients - 1];

	nr_clients--;
	tb->nr_clients = nr_clients;
	if (nr_clients == 0) {
		free(clients);
		tb->clients = NULL;
	} else {
		clients = realloc(clients, sizeof(*clients) * nr_clients);
		if (!clients) {
			pr_warn("Failed to shrink memory for clients");
			return 0;
		}

		tb->clients = clients;
	}

	return 0;
}

static uint32_t ____put_token_bucket(struct server_ctx *ctx,
				     struct token_bucket *tb,
				     struct client_state *c)
	__must_hold(&ctx->rl.lock)
	__must_hold(&tb->lock)
{
	uint32_t ref;

	if (c) {
		assert(tb->nr_clients > 0);
		assert(tb->ref_cnt >= 2);
		del_client_from_tbucket(tb, c);
	}

	ref = --tb->ref_cnt;
	if (ref == 0) {
		assert(tb->nr_clients == 0);
		assert(tb->timer_fd >= 0);
		del_token_bucket_from_rl(&ctx->rl, tb);
		pthread_mutex_unlock(&tb->lock);
		pthread_mutex_destroy(&tb->lock);
		close_fd_p(&tb->timer_fd);
		pr_debug("put: Token bucket destroyed (addr=%s)", addr_to_str(&tb->addr));
		free(tb);
		return 0;
	} else {
		pr_debug("put: Token bucket ref count: %u (addr=%s)", ref, addr_to_str(&tb->addr));
		return ref;
	}
}

static uint32_t __put_token_bucket(struct server_ctx *ctx, struct token_bucket *tb,
				   struct client_state *c)
	__must_hold(&ctx->rl.lock)
{
	uint32_t ref;

	pthread_mutex_lock(&tb->lock);

	/*
	 * If it returns 0, it means that the token bucket has
	 * been destroyed. No need to unlock the mutex.
	 */
	ref = ____put_token_bucket(ctx, tb, c);
	if (ref > 0)
		pthread_mutex_unlock(&tb->lock);

	return ref;
}

static uint32_t put_token_bucket(struct server_ctx *ctx, struct token_bucket *tb,
				 struct client_state *c)
{
	uint32_t ref;

	pthread_mutex_lock(&ctx->rl.lock);
	ref = __put_token_bucket(ctx, tb, c);
	pthread_mutex_unlock(&ctx->rl.lock);
	return ref;
}

static struct token_bucket *find_or_create_token_bucket(struct server_ctx *ctx,
							const struct in46_addr *addr,
							struct client_state *c)
{
	struct token_bucket *tb;
	int ret;

	pthread_mutex_lock(&ctx->rl.lock);
	tb = __find_token_bucket(&ctx->rl, addr);
	if (!tb) {
		tb = create_token_bucket(ctx, addr);
		if (unlikely(!tb))
			goto out;
	}

	pthread_mutex_lock(&tb->lock);
	ret = add_client_to_tbucket(tb, c);
	if (unlikely(ret)) {
		pr_error("Failed to add client to token bucket: %s", strerror(-ret));
		tb = NULL;
	} else {
		tb->ref_cnt++;
		assert(tb->ref_cnt >= 2);
	}
	pthread_mutex_unlock(&tb->lock);

out:
	pthread_mutex_unlock(&ctx->rl.lock);
	return tb;
}

static void free_rate_limit(struct server_ctx *ctx)
{
	struct rate_limit *rl = &ctx->rl;
	uint32_t i;

	if (!rl->tbuckets)
		return;

	pthread_mutex_lock(&rl->lock);
	pthread_mutex_unlock(&rl->lock);

	for (i = 0; i < rl->nr_tbuckets; i++) {
		struct token_bucket *tb = rl->tbuckets[i];
		uint32_t ref;

		ref = put_token_bucket(ctx, tb, NULL);
		if (ref > 0)
			pr_warn("Token bucket still has %u references", ref);
	}

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
	memset(&c->target_addr, 0, sizeof(c->target_addr));
	c->tbucket = NULL;
	c->is_up_rate_limited = false;
	c->is_down_rate_limited = false;
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
	uint32_t i;

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

		if (c->tbucket)
			put_token_bucket(w->ctx, c->tbucket, c);
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
		pr_info("Starting sub worker %u", w->idx);
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

	free_clients(w);
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
	ctx->should_stop = true;
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
		if (ctx->cfg.nr_workers > 1)
			w = &ctx->workers[1];

		data.u64 = EPL_DT_UDP_FD;
		ret = epoll_add(w, ctx->udp_fd, EPOLLIN, data);
		if (ret)
			return ret;
	}

	return 0;
}

static struct server_wrk *pick_worker_for_new_conn(struct server_ctx *ctx,
						   struct sockaddr_in46 *taddr)
{
	struct server_wrk *w = NULL;
	uint32_t i, min;

	(void)taddr;
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

	if (c->tbucket) {
		assert(w->ctx->cfg.using_rate_limit);
		put_token_bucket(w->ctx, c->tbucket, c);
		c->tbucket = NULL;
	}

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
		pr_vinfo("Closing a client connection (cfd=%d; tfd=%d; src=%s; thread=%u)",
			 c->client_fd, c->target_fd, sockaddr_to_str(&c->client_addr), w->idx);

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

	c->is_up_rate_limited = false;
	c->is_down_rate_limited = false;
	c->wrk_ref = NULL;
	c->cpoll_mask = 0;
	c->tpoll_mask = 0;
	w->handle_events_should_break = handle_events_should_break;
	atomic_fetch_sub(&w->nr_active_clients, 1u);

	memset(&c->client_addr, 0, sizeof(c->client_addr));
	memset(&c->target_addr, 0, sizeof(c->target_addr));

	ret = push_client_stack(w->cl_stack, c->idx);
	assert(!ret);
	(void)ret;
}

static int prepare_tcp_target_connect(struct server_wrk *w, struct sockaddr_in46 *taddr)
{
	int ret, tmp, fd, family = taddr->sa.sa_family;
	socklen_t len;

	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

#ifdef TCP_NODELAY
	ret = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret));
#endif

	if (w->ctx->cfg.run_as_tproxy_tcp) {
		tmp = 0x7777;
		ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &tmp, sizeof(tmp));
		if (ret) {
			ret = -errno;
			pr_error("Failed to set SO_MARK: %s", strerror(-ret));
			close_fd_p(&fd);
			return ret;
		}
	}

	len = get_sockaddr_len(taddr);
	ret = connect(fd, &taddr->sa, len);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			close_fd_p(&fd);
			return -ret;
		}
	}

	return fd;
}

static int get_target_addr(struct server_wrk *w, int family_hint, int fd,
			   struct sockaddr_in46 *taddr)
{
	struct sockaddr_in46 *cfg_taddr = &w->ctx->cfg.tcp_target_addr;
	socklen_t len, alt_len;
	int ret, lvl, alt_lvl;

	if (!w->ctx->cfg.run_as_tproxy_tcp) {
		*taddr = *cfg_taddr;
		assert(!is_addr_any(taddr));
		return 0;
	}

	memset(taddr, 0, sizeof(*taddr));
	if (family_hint == AF_INET6) {
		len = sizeof(taddr->in6);
		lvl = SOL_IPV6;
		alt_len = sizeof(taddr->in4);
		alt_lvl = SOL_IP;
	} else {
		len = sizeof(taddr->in4);
		lvl = SOL_IP;
		alt_len = sizeof(taddr->in6);
		alt_lvl = SOL_IPV6;
	}

	ret = getsockopt(fd, lvl, SO_ORIGINAL_DST, &taddr->sa, &len);
	if (!ret)
		return 0;

	ret = getsockopt(fd, alt_lvl, SO_ORIGINAL_DST, &taddr->sa, &alt_len);
	if (ret)
		return -errno;

	return 0;
}

static int register_new_tcp_client(struct server_ctx *ctx, int fd,
				   struct sockaddr_in46 *addr)
{
	int target_fd, ret, family_hint;
	struct sockaddr_in46 taddr;
	struct token_bucket *tb;
	struct client_state *c;
	union epoll_data data;
	struct server_wrk *w;

	w = pick_worker_for_new_conn(ctx, addr);
	c = get_free_client_slot(w);
	if (unlikely(!c)) {
		pr_error("Failed to get a free client slot (cfd=%d; src=%s; thread=%u)",
			 fd, sockaddr_to_str(addr), w->idx);
		return -EAGAIN;
	}

	c->wrk_ref = w;

	if (ctx->cfg.using_rate_limit) {
		struct in46_addr key_addr;

		if (addr->sa.sa_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
				key_addr.family = 4;
				memcpy(&key_addr.in4, &addr->in6.sin6_addr.s6_addr[12], sizeof(key_addr.in4));
			} else {
				key_addr.family = 6;
				key_addr.in6 = addr->in6.sin6_addr;
			}
		} else {
			key_addr.family = 4;
			key_addr.in4 = addr->in4.sin_addr;
		}

		tb = find_or_create_token_bucket(ctx, &key_addr, c);
		if (unlikely(!tb)) {
			put_client_slot(w, c);
			return -ENOMEM;
		}
		c->tbucket = tb;
	}

	if (ctx->cfg.run_as_tproxy_tcp) {
		if (addr->sa.sa_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr))
				family_hint = AF_INET;
			else
				family_hint = AF_INET6;
		} else {
			family_hint = AF_INET;
		}
	} else {
		family_hint = ctx->cfg.tcp_target_addr.sa.sa_family;
	}

	ret = get_target_addr(w, family_hint, fd, &taddr);
	if (unlikely(ret < 0)) {
		put_client_slot(w, c);
		return ret;
	}

	target_fd = prepare_tcp_target_connect(w, &taddr);
	if (unlikely(target_fd < 0)) {
		pr_error("Failed to prepare target connect: %s (cfd=%d; src=%s; dst=%s; thread=%u)",
			 strerror(-target_fd), fd, sockaddr_to_str(addr),
			 sockaddr_to_str(&taddr), w->idx);
		put_client_slot(w, c);
		return target_fd;
	}

	c->target_fd = target_fd;
	c->client_fd = fd;
	c->client_addr = *addr;
	c->target_addr = taddr;

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
	c->cpoll_mask = 0;
	ret = epoll_add(w, c->client_fd, c->cpoll_mask, data);
	if (unlikely(ret)) {
		pr_error("Failed to add client FD to epoll: %s (cfd=%d; tfd=%d; src=%s; dst=%s; thread=%u)",
			 strerror(ret), c->client_fd, c->target_fd,
			 sockaddr_to_str(&c->client_addr),
			 sockaddr_to_str(&c->target_addr), w->idx);
		goto out_err_epl;
	}

	data.ptr = c;
	data.u64 |= EPL_DT_MASK_TARGET_TCP_CONNECT;
	c->tpoll_mask = EPOLLOUT | EPOLLIN;
	ret = epoll_add(w, c->target_fd, c->tpoll_mask, data);
	if (unlikely(ret)) {
		pr_error("Failed to add target FD to epoll: %s (cfd=%d; tfd=%d; src=%s; dst=%s; thread=%u)",
			 strerror(ret), c->client_fd, c->target_fd,
			 sockaddr_to_str(&c->client_addr),
			 sockaddr_to_str(&c->target_addr), w->idx);
		epoll_del(w, c->client_fd);
		goto out_err_epl;
	}

	pr_debug("Preparing forward conn from %s to %s (cfd=%d; tfd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_addr),
		 sockaddr_to_str(&c->target_addr),
		 c->client_fd, c->target_fd, w->idx);

	send_event_fd(w);
	return 0;

out_err_epl:
	close_fd_p(&c->target_fd);
	close_fd_p(&c->client_fd);
	put_client_slot(w, c);
	return ret;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN)
		return -EAGAIN;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		w->ctx->accept_need_rearm = true;
		return epoll_del(w, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static int __handle_event_tcp_accept(struct server_wrk *w)
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
		pr_error("accept() returned invalid address length: %u (fd=%d; thread=%u)", len, fd, w->idx);
		close_fd_p(&fd);
		return -EINVAL;
	}

	ret = set_fd_nonblock(fd);
	if (unlikely(ret < 0)) {
		pr_error("Failed to set client FD non-blocking: %s (fd=%d; src=%s; thread=%u)",
			 strerror(-ret), fd, sockaddr_to_str(&addr), w->idx);
		close_fd_p(&fd);
		return ret;
	}

	pr_vinfo("New conn from %s (fd=%d; thread=%u)", sockaddr_to_str(&addr),
		 fd, w->idx);

	ret = register_new_tcp_client(ctx, fd, &addr);
	if (ret < 0)
		close_fd_p(&fd);

	return 0;
}

static int handle_event_tcp_accept(struct server_wrk *w)
{
	uint32_t i = 0;
	int ret;

	do {
		ret = __handle_event_tcp_accept(w);
		if (ret == -EAGAIN)
			break;

		if (unlikely(ret))
			return ret;
	} while (++i < 16);

	if (i > 1)
		pr_vinfo("Handled %u accept events", i);

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
	(void)w;
	(void)ev;
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
	union epoll_data data;
	socklen_t len;
	int ret, tmp;

	tmp = 0;
	len = sizeof(tmp);
	ret = getsockopt(c->target_fd, SOL_SOCKET, SO_ERROR, &tmp, &len);
	if (unlikely(ret)) {
		ret = errno;
		pr_error("Failed to get target socket error: %s (cfd=%d; tfd=%d; src=%s; dst=%s; thread=%u)",
			 strerror(ret), c->client_fd, c->target_fd,
			 sockaddr_to_str(&c->client_addr),
			 sockaddr_to_str(&c->target_addr), w->idx);
		put_client_slot(w, c);
		return 0;
	}

	if (tmp) {
		pr_error("Target connect error: %s (cfd=%d; tfd=%d; src=%s; dst=%s; thread=%u)",
			 strerror(tmp), c->client_fd, c->target_fd,
			 sockaddr_to_str(&c->client_addr),
			 sockaddr_to_str(&c->target_addr), w->idx);
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
		pr_error("Failed to allocate memory for buffers (cfd=%d; tfd=%d; src=%s; dst=%s; thread=%u)",
			 c->client_fd, c->target_fd, sockaddr_to_str(&c->client_addr),
			 sockaddr_to_str(&c->target_addr), w->idx);
		put_client_slot(w, c);
		return -ENOMEM;
	}

	pr_vinfo("Fwd conn established from %s to %s (client_fd=%d; target_fd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_addr), sockaddr_to_str(&c->target_addr),
		 c->target_fd, c->client_fd, w->idx);

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

static size_t get_max_down_bytes(struct token_bucket *tb)
{
	int64_t tokens;
	uint32_t nr;
	size_t ret;

	if (!tb)
		return SPLICE_BUF_SIZE;

	tokens = atomic_load(&tb->download_tokens);
	nr = atomic_load(&tb->nr_clients);

	assert(nr > 0);
	if (tokens <= 0) {
		ret = 0;
	} else {
		ret = (size_t)(tokens / nr) / 2;
		if (!ret)
			ret = 1;
	}

	return ret;
}

static size_t get_max_up_bytes(struct token_bucket *tb)
{
	int64_t tokens;
	uint32_t nr;
	size_t ret;

	if (!tb)
		return SPLICE_BUF_SIZE;

	tokens = atomic_load(&tb->upload_tokens);
	nr = atomic_load(&tb->nr_clients);

	assert(nr > 0);
	if (tokens <= 0) {
		ret = 0;
	} else {
		ret = (size_t)(tokens / nr) / 2;
		if (!ret)
			ret = 1;
	}

	return ret;
}

static int mark_client_up_rate_limited(struct client_state *c)
{
	struct server_wrk *w = c->wrk_ref;
	union epoll_data data;
	int ret;

	if (c->is_up_rate_limited)
		return 0;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
	c->cpoll_mask &= ~EPOLLIN;
	ret = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
	c->is_up_rate_limited = true;
	atomic_fetch_add(&c->tbucket->nr_up_rate_limted, 1u);
	pr_debug("Client %s is upload rate limited", sockaddr_to_str(&c->client_addr));
	return ret;
}

static int mark_client_down_rate_limited(struct client_state *c)
{
	struct server_wrk *w = c->wrk_ref;
	union epoll_data data;
	int ret;

	if (c->is_down_rate_limited)
		return 0;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
	c->tpoll_mask &= ~EPOLLIN;
	ret = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
	c->is_down_rate_limited = true;
	atomic_fetch_add(&c->tbucket->nr_down_rate_limted, 1u);
	pr_debug("Client %s is download rate limited", sockaddr_to_str(&c->client_addr));
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

	if (events & (EPOLLERR | EPOLLHUP)) {
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		size_t max_down = get_max_down_bytes(c->tbucket);

		if (max_down > 0) {
			sb.buf = c->tbuf;
			sb.cur_len = c->tbuf_len;
			sb.max_len = SPLICE_BUF_SIZE;
			sb.max_recv = max_down;
			sb.max_send = max_down;
			ret = do_tcp_splice(c->target_fd, c->client_fd, &sb);
			if (unlikely(ret < 0)) {
				put_client_slot(w, c);
				return 0;
			}

			if (w->ctx->cfg.using_rate_limit)
				atomic_fetch_sub(&c->tbucket->download_tokens, (int64_t)ret);

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
		} else {
			ret = mark_client_down_rate_limited(c);
			if (unlikely(ret)) {
				put_client_slot(w, c);
				return 0;
			}
		}
	}

	if (events & EPOLLOUT) {
		size_t max_up = get_max_up_bytes(c->tbucket);

		if (max_up > 0) {
			sb.buf = c->cbuf;
			sb.cur_len = c->cbuf_len;
			sb.max_len = SPLICE_BUF_SIZE;
			sb.max_recv = max_up;
			sb.max_send = max_up;
			ret = do_tcp_splice(c->client_fd, c->target_fd, &sb);
			if (unlikely(ret < 0)) {
				put_client_slot(w, c);
				return 0;
			}

			if (w->ctx->cfg.using_rate_limit)
				atomic_fetch_sub(&c->tbucket->upload_tokens, (int64_t)ret);

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
		} else {
			ret = mark_client_up_rate_limited(c);
			if (unlikely(ret)) {
				put_client_slot(w, c);
				return 0;
			}
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

	if (events & (EPOLLERR | EPOLLHUP)) {
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		size_t max_up = get_max_up_bytes(c->tbucket);

		if (max_up > 0) {
			sb.buf = c->cbuf;
			sb.cur_len = c->cbuf_len;
			sb.max_len = SPLICE_BUF_SIZE;
			sb.max_recv = max_up;
			sb.max_send = max_up;
			ret = do_tcp_splice(c->client_fd, c->target_fd, &sb);
			if (unlikely(ret < 0)) {
				put_client_slot(w, c);
				return 0;
			}

			if (w->ctx->cfg.using_rate_limit)
				atomic_fetch_sub(&c->tbucket->upload_tokens, (int64_t)ret);

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
		} else {
			ret = mark_client_up_rate_limited(c);
			if (unlikely(ret)) {
				put_client_slot(w, c);
				return 0;
			}
		}
	}

	if (events & EPOLLOUT) {
		size_t max_down = get_max_down_bytes(c->tbucket);

		if (max_down > 0) {
			sb.buf = c->tbuf;
			sb.cur_len = c->tbuf_len;
			sb.max_len = SPLICE_BUF_SIZE;
			sb.max_recv = max_down;
			sb.max_send = max_down;
			ret = do_tcp_splice(c->target_fd, c->client_fd, &sb);
			if (unlikely(ret < 0)) {
				put_client_slot(w, c);
				return 0;
			}

			if (w->ctx->cfg.using_rate_limit)
				atomic_fetch_sub(&c->tbucket->download_tokens, (int64_t)ret);

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
		} else {
			ret = mark_client_down_rate_limited(c);
			if (unlikely(ret)) {
				put_client_slot(w, c);
				return 0;
			}
		}
	}

	return 0;
}


static int fill_token_bucket(struct server_wrk *w, struct token_bucket *tb)
{
	uint32_t i, n;
	int64_t tmp;

	pthread_mutex_lock(&tb->lock);
	pr_debug("NR clients of (%s): %u", addr_to_str(&tb->addr), tb->nr_clients);
	if (tb->nr_clients == 0) {
		/*
		 * Keep the lock ordering: w->ctx->rl.lock -> tb->lock
		 */
		pthread_mutex_unlock(&tb->lock);
		pthread_mutex_lock(&w->ctx->rl.lock);
		pthread_mutex_lock(&tb->lock);

		/*
		 * Re-check the number of clients, because it might have
		 * changed while we were waiting for the lock.
		 */
		if (tb->nr_clients == 0) {
			uint32_t ref = ____put_token_bucket(w->ctx, tb, NULL);
			if (ref > 0) {
				pthread_mutex_unlock(&tb->lock);
				pthread_mutex_unlock(&w->ctx->rl.lock);
				return 0;
			}
			assert(ref == 0);
		}

		pthread_mutex_unlock(&tb->lock);
		pthread_mutex_unlock(&w->ctx->rl.lock);
		return 0;
	}

	tmp = atomic_load(&tb->download_tokens);
	tmp += tb->max_download_tokens;
	if (tmp > tb->max_download_tokens)
		tmp = tb->max_download_tokens;
	atomic_store(&tb->download_tokens, tmp);

	n = atomic_load(&tb->nr_down_rate_limted);
	if (n) {
		for (i = 0; i < tb->nr_clients; i++) {
			struct client_state *c = tb->clients[i];
			struct server_wrk *cw = c->wrk_ref;
			union epoll_data data;
			int ret;

			if (!n)
				break;

			if (!c->is_down_rate_limited)
				continue;

			c->is_down_rate_limited = false;
			atomic_fetch_sub(&tb->nr_down_rate_limted, 1u);
			n--;

			data.u64 = 0;
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_TARGET_TCP_DATA;
			c->tpoll_mask |= EPOLLIN;
			ret = epoll_mod(cw, c->target_fd, c->tpoll_mask, data);
			assert(!ret);
			(void)ret;
		}
	}

	tmp = atomic_load(&tb->upload_tokens);
	tmp += tb->max_upload_tokens;
	if (tmp > tb->max_upload_tokens)
		tmp = tb->max_upload_tokens;
	atomic_store(&tb->upload_tokens, tmp);

	n = atomic_load(&tb->nr_up_rate_limted);
	if (n) {
		for (i = 0; i < tb->nr_clients; i++) {
			struct client_state *c = tb->clients[i];
			struct server_wrk *cw = c->wrk_ref;
			union epoll_data data;
			int ret;

			if (!n)
				break;

			if (!c->is_up_rate_limited)
				continue;

			c->is_up_rate_limited = false;
			atomic_fetch_sub(&tb->nr_up_rate_limted, 1u);
			n--;

			data.u64 = 0;
			data.ptr = c;
			data.u64 |= EPL_DT_MASK_CLIENT_TCP_DATA;
			c->cpoll_mask |= EPOLLIN;
			ret = epoll_mod(cw, c->client_fd, c->cpoll_mask, data);
			assert(!ret);
			(void)ret;
		}
	}

	pthread_mutex_unlock(&tb->lock);
	return 0;
}

static int handle_event_timer(struct server_wrk *w, struct epoll_event *ev)
{
	struct token_bucket *tb = ev->data.ptr;
	uint64_t nr_exps;
	ssize_t ret;

	ret = read(tb->timer_fd, &nr_exps, sizeof(nr_exps));
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_warn("Failed to read from timer FD %s: %s", addr_to_str(&tb->addr), strerror(ret));
	} else if (unlikely(ret != sizeof(nr_exps))) {
		pr_warn("Unexpected read size from timer FD %s: %zd", addr_to_str(&tb->addr), ret);
	}

	return fill_token_bucket(w, tb);
}

static int poll_events(struct server_wrk *w)
{
	int ret;

	w->handle_events_should_break = false;
	ret = epoll_wait(w->ep_fd, w->events, NR_EPOLL_EVENTS, w->ep_timeout);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EINTR) {
			pr_info("epoll_wait() interrupted");
			return 0;
		}

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

	mask = ev->data.u64 & EPL_DT_MASK_ALL;
	ev->data.u64 &= ~EPL_DT_MASK_ALL;

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
	case EPL_DT_MASK_TIMER:
		return handle_event_timer(w, ev);
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
		pr_info("The main worker is ready! (worker 0)");

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

static int init_server_ctx(struct server_ctx *ctx)
{
	int ret;

	set_default_server_ctx(ctx);
	try_increase_rlimit_nofile();

	g_verbose = ctx->cfg.verbose;
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ret = init_rate_limit(ctx);
	if (ret)
		return ret;

	ret = init_socket(ctx);
	if (ret) {
		free_rate_limit(ctx);
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
