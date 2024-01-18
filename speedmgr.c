// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

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

#if 1
#define pr_debug(fmt, ...) printf("debug: " fmt "\n", ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do { } while (0)
#endif

#define pr_error(fmt, ...) printf("error: " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) printf("info: " fmt "\n", ##__VA_ARGS__)

struct sockaddr_in46 {
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
};

struct client_state {
	int			client_fd;
	int			target_fd;
	struct sockaddr_in46	client_addr;
};

struct server_ctx;

/*
 * Each worker has its epoll FD.
 */
struct server_wrk {
	int			ep_fd;
	int			ev_fd;
	uint32_t		idx;
	pthread_t		thread;
	struct server_ctx	*ctx;
};

struct server_cfg {
	uint8_t			verbose;
	int			backlog;
	uint32_t		nr_workers;
	struct sockaddr_in46	bind_addr;
	struct sockaddr_in46	target_addr;
};

struct server_ctx {
	volatile bool		should_stop;
	int			tcp_fd;
	struct server_wrk	*workers;
	struct server_cfg	cfg;
};

enum {
	EPOLL_EV_FD_DATA  = 0,
	EPOLL_TCP_FD_DATA = 1
};

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif

struct option long_options[] = {
	{ "help",	no_argument,		NULL,	'h' },
	{ "version",	no_argument,		NULL,	'V' },
	{ "workers",	required_argument,	NULL,	'w' },
	{ "bind",	required_argument,	NULL,	'b' },
	{ "target",	required_argument,	NULL,	't' },
	{ "verbose",	no_argument,		NULL,	'v' },
	{ "backlog",	required_argument,	NULL,	'B' },
	{ NULL,		0,			NULL,	0 },
};

static void show_help(const char *app)
{
	printf("\nUsage: %s [options]\n\n", app);
	printf("Options:\n");
	printf("  -h, --help\t\t\tShow this help message\n");
	printf("  -v, --version\t\t\tShow version\n");
	printf("  -w, --workers <number>\tNumber of workers\n");
	printf("  -b, --bind ip:port\t\tBind to IP and port\n");
	printf("  -t, --target ip:port\t\tTarget IP and port\n");
	printf("  -V, --verbose\t\t\tVerbose output\n\n");
	printf("  -B, --backlog <number>\tTCP backlog\n\n");
}

static int parse_addr_and_port(const char *str, struct sockaddr_in46 *out)
{
	char *addr, *port;
	in_port_t *port_p;
	int ret;

	addr = strdup(str);
	if (!addr)
		return -ENOMEM;

	port = strchr(addr, ':');
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
	} p;

	cfg->backlog = 64;
	cfg->nr_workers = 4;

	memset(&p, 0, sizeof(p));
	while (1) {
		int c, tmp;

		c = getopt_long(argc, argv, "hVw:b:t:vB:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			exit(EXIT_SUCCESS);
		case 'V':
			printf("speedmgr version 0.1");
			exit(EXIT_SUCCESS);
		case 'w':
			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 1024) {
				pr_error("Invalid number of workers: %d", tmp);
				return -EINVAL;
			}
			cfg->nr_workers = (uint32_t)tmp;
			break;
		case 'b':
			p.got_bind_addr = true;
			tmp = parse_addr_and_port(optarg, &cfg->bind_addr);
			if (tmp)
				return tmp;
			break;
		case 't':
			p.got_target_addr = true;
			tmp = parse_addr_and_port(optarg, &cfg->target_addr);
			if (tmp)
				return tmp;
			break;
		case 'v':
			cfg->verbose = 1;
			break;
		case 'B':
			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 1024) {
				pr_error("Invalid TCP backlog: %d", tmp);
				return -EINVAL;
			}
			cfg->backlog = tmp;
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

static volatile bool *g_stop;

static void signal_handler(int sig)
{
	*g_stop = true;
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

static int init_socket(struct server_ctx *ctx)
{
	int tcp_fd, ret, family;
	socklen_t len;

	family = ctx->cfg.bind_addr.sa.sa_family;
	tcp_fd = socket(family, SOCK_STREAM, 0);
	if (tcp_fd < 0) {
		pr_error("Failed to create socket: %s", strerror(errno));
		return -errno;
	}

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
		ret = -errno;
		pr_error("Failed to add FD %d to epoll: %s", fd, strerror(-ret));
		return ret;
	}

	return 0;
}

static int epoll_del(struct server_wrk *w, int fd)
{
	int ret;

	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, fd, NULL);
	if (ret) {
		ret = -errno;
		pr_error("Failed to delete FD %d from epoll: %s", fd, strerror(-ret));
		return ret;
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
		ret = -errno;
		pr_error("Failed to modify FD %d in epoll: %s\n", fd, strerror(-ret));
		return ret;
	}

	return 0;
}

static int init_epoll(struct server_wrk *w)
{
	int ep_fd, ev_fd, ret;
	union epoll_data data;

	ep_fd = epoll_create1(0);
	if (ep_fd < 0) {
		pr_error("Failed to create epoll FD: %s", strerror(errno));
		return -errno;
	}

	ev_fd = eventfd(0, EFD_NONBLOCK);
	if (ev_fd < 0) {
		ret = -errno;
		pr_error("Failed to create event FD: %s", strerror(-ret));
		close(ep_fd);
		return ret;
	}

	w->ep_fd = ep_fd;
	w->ev_fd = ev_fd;
	data.u64 = EPOLL_EV_FD_DATA;
	ret = epoll_add(w, ev_fd, EPOLLIN, data);
	if (ret) {
		close(ev_fd);
		close(ep_fd);
		w->ep_fd = -1;
		w->ev_fd = -1;
		return ret;
	}

	return 0;
}

static void free_epoll(struct server_wrk *w)
{
	if (w->ep_fd >= 0)
		close(w->ep_fd);

	if (w->ev_fd >= 0)
		close(w->ev_fd);
}

static int init_worker(struct server_wrk *w, uint32_t idx)
{
	union epoll_data data;
	int ret;

	ret = init_epoll(w);
	if (ret)
		return ret;

	if (idx == 0) {
		data.u64 = EPOLL_TCP_FD_DATA;
		ret = epoll_add(w, w->ctx->tcp_fd, EPOLLIN, data);
		if (ret)
			return ret;
	}

	return 0;
}

static void send_event_fd(struct server_wrk *w)
{
	uint64_t val = 1;
	int ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val))
		pr_error("Failed to write to event FD: %s (thread %u)", strerror(errno), w->idx);
}

static void consume_event_fd(struct server_wrk *w)
{
	uint64_t val;
	int ret;

	ret = read(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val))
		pr_error("Failed to read from event FD: %s (thread %u)", strerror(errno), w->idx);
}

static void free_worker(struct server_wrk *w)
{
	if (w->ctx) {
		send_event_fd(w);
		pr_info("Joining worker thread %u...", w->idx);
		pthread_join(w->thread, NULL);
		pr_info("Worker thread %u joined", w->idx);
	}

	free_epoll(w);
}

static void *worker_func(void *data);

static int init_workers(struct server_ctx *ctx)
{
	int ret = 0;
	uint32_t i;

	ctx->workers = calloc(ctx->cfg.nr_workers, sizeof(*ctx->workers));
	if (!ctx->workers)
		return -ENOMEM;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct server_wrk *w = &ctx->workers[i];

		w->idx = i;
		w->ctx = ctx;
		w->ep_fd = -1;
		w->ev_fd = -1;
		ret = init_worker(w, i);
		if (ret) {
			w->ctx = NULL;
			goto out_err;
		}

		/*
		 * The first worker will run in the main thread.
		 */
		if (i == 0)
			continue;

		ret = pthread_create(&w->thread, NULL, worker_func, w);
		if (ret) {
			ret = -errno;
			pr_error("Failed to create worker thread: %s", strerror(-ret));
			w->ctx = NULL;
			goto out_err;
		}
	}

	return ret;

out_err:
	ctx->should_stop = true;
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
	return;
}

static int init_ctx(struct server_ctx *ctx)
{
	int ret;

	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ctx->should_stop = false;
	ctx->tcp_fd = -1;
	ret = init_socket(ctx);
	if (ret)
		return ret;

	ret = init_workers(ctx);
	if (ret) {
		free_socket(ctx);
		return ret;
	}

	return 0;
}

static void free_ctx(struct server_ctx *ctx)
{
	ctx->should_stop = true;
	free_workers(ctx);
	free_socket(ctx);
}

static void *worker_func(void *data)
{
	struct server_wrk *w = data;
	struct server_ctx *ctx = w->ctx;

	pr_info("Worker thread %u started", w->idx);
	while (!ctx->should_stop) {
	}

	return NULL;
}

static int run_main_worker(struct server_ctx *ctx)
{
	long ret;
	void *p;

	p = worker_func(&ctx->workers[0]);
	ret = (long)p;

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

	ret = run_main_worker(&ctx);
	free_ctx(&ctx);
	return 0;
}
