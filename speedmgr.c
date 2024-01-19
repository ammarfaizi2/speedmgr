// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#define NR_EPOLL_EVENTS		64
#define NR_CLIENTS		2048
#define SPLICE_BUF_SIZE		8192

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
	uint32_t		cpoll_mask;
	uint32_t		tpoll_mask;
	uint32_t		idx;
	size_t			cbuf_len;
	size_t			tbuf_len;
	char			*cbuf;
	char			*tbuf;
	struct sockaddr_in46	client_addr;
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
	int			timeout;
	uint32_t		idx;
	uint32_t		nr_clients;
	_Atomic(uint32_t)	nr_active_clients;
	pthread_t		thread;
	struct server_ctx	*ctx;
	struct client_state	*clients;
	struct client_stack	*cl_stack;
	struct epoll_event	events[NR_EPOLL_EVENTS];
	volatile bool		handle_events_should_stop;
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
	bool			accept_stopped;
	int			tcp_fd;
	struct server_wrk	*workers;
	struct server_cfg	cfg;
};

enum {
	EPOLL_EV_FD_DATA          = 0,
	EPOLL_TCP_FD_DATA         = 1,
	EPOLL_TARGET_CONNECT_MASK = (0x0001ull << 48ull),
	EPOLL_TARGET_EVENT_MASK   = (0x0002ull << 48ull),
	EPOLL_CLIENT_EVENT_MASK   = (0x0003ull << 48ull),
};

#define EPOLL_DATA_MASK (0xffffull << 48ull)

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
	int ep_fd, ev_fd, ret;
	union epoll_data data;

	ep_fd = epoll_create(300);
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

	ret = set_fd_nonblock(ev_fd);
	if (ret) {
		close(ev_fd);
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

	size = sizeof(*cl_stack) + (sizeof(*cl_stack->data) * NR_CLIENTS);
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
	cl_stack->bp = NR_CLIENTS;
	for (i = NR_CLIENTS; i > 0; i--)
		__push_client_stack(cl_stack, i - 1);

	w->cl_stack = cl_stack;
	return 0;
}

static void init_client_state(struct client_state *c)
{
	c->client_fd = -1;
	c->target_fd = -1;
	c->cbuf = NULL;
	c->tbuf = NULL;
	c->cbuf_len = 0;
	c->tbuf_len = 0;
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

	w->nr_clients = NR_CLIENTS;
	clients = calloc(w->nr_clients, sizeof(*clients));
	if (!clients) {
		free_client_stack(w);
		return -ENOMEM;
	}

	for (i = 0; i < w->nr_clients; i++) {
		init_client_state(&clients[i]);
		clients[i].idx = i;
	}

	w->clients = clients;
	return 0;
}

static void close_all_client_fds(struct server_wrk *w)
{
	uint32_t i;

	for (i = 0; i < w->nr_clients; i++) {
		struct client_state *c = &w->clients[i];

		if (c->client_fd >= 0) {
			close(c->client_fd);
			c->client_fd = -1;
		}

		if (c->target_fd >= 0) {
			close(c->target_fd);
			c->target_fd = -1;
		}

		if (c->cbuf) {
			free(c->cbuf);
			c->cbuf = NULL;
			c->cbuf_len = 0;
		}

		if (c->tbuf) {
			free(c->tbuf);
			c->tbuf = NULL;
			c->tbuf_len = 0;
		}
	}
}

void free_clients(struct server_wrk *w)
{
	if (!w->clients)
		return;

	close_all_client_fds(w);
	free(w->clients);
	w->clients = NULL;
	free_client_stack(w);
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
	return c;
}

static void put_client_slot(struct server_wrk *w, struct client_state *c)
{
	bool hess = false;
	int ret;

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
		pr_infov("Closing client FD %d (src: %s) (thread %u)", c->client_fd,
			 sockaddr_to_str(&c->client_addr), w->idx);
		ret = epoll_del(w, c->client_fd);
		assert(!ret);
		close(c->client_fd);
		c->client_fd = -c->client_fd;
		hess = true;
	}

	if (c->target_fd >= 0) {
		ret = epoll_del(w, c->target_fd);
		assert(!ret);
		close(c->target_fd);
		c->target_fd = -c->target_fd;
		hess = true;
	}

	if (hess && w->ctx->accept_stopped) {
		union epoll_data data;

		pr_info("Re-enabling accept() (thread %u)", w->idx);
		data.u64 = EPOLL_TCP_FD_DATA;
		ret = epoll_add(w, w->ctx->tcp_fd, EPOLLIN, data);
		assert(!ret);

		w->ctx->accept_stopped = false;
		send_event_fd(&w->ctx->workers[0]);
	}

	w->handle_events_should_stop = hess;
	memset(&c->client_addr, 0, sizeof(c->client_addr));
	ret = push_client_stack(w->cl_stack, c->idx);
	assert(!ret);
	(void)ret;
}

static void free_worker(struct server_wrk *w)
{
	if (w->ctx && w->idx != 0) {
		send_event_fd(w);
		pr_info("Joining worker thread %u...", w->idx);
		pthread_join(w->thread, NULL);
		pr_info("Worker thread %u joined", w->idx);
	}

	free_clients(w);
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

		w->clients = NULL;
		ret = init_clients(w);
		if (ret < 0)
			goto out_err;

		w->idx = i;
		w->ctx = ctx;
		w->ep_fd = -1;
		w->ev_fd = -1;
		w->timeout = 5000;
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

static int init_ctx(struct server_ctx *ctx)
{
	int ret;

	g_verbose = ctx->cfg.verbose;
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	try_increase_rlimit_nofile();
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

static int poll_events(struct server_wrk *w)
{
	int ret;

	w->handle_events_should_stop = false;
	ret = epoll_wait(w->ep_fd, w->events, NR_EPOLL_EVENTS, w->timeout);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EINTR)
			return 0;

		pr_error("epoll_wait() failed: %s", strerror(ret));
		return -ret;
	}

	return ret;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		w->ctx->accept_stopped = true;
		return epoll_del(w, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static struct server_wrk *pick_worker_for_new_conn(struct server_ctx *ctx)
{
	struct server_wrk *w = NULL;
	uint32_t i, min;

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

	c->target_fd = fd;

	data.ptr = c;
	data.u64 |= EPOLL_CLIENT_EVENT_MASK;
	c->cpoll_mask = 0;
	ret = epoll_add(w, c->client_fd, c->cpoll_mask, data);
	if (ret)
		return ret;

	data.ptr = c;
	data.u64 |= EPOLL_TARGET_CONNECT_MASK;
	c->tpoll_mask = EPOLLOUT | EPOLLIN;
	ret = epoll_add(w, c->target_fd, c->tpoll_mask, data);
	if (ret)
		return ret;

	send_event_fd(w);
	pr_debug("Preparing forward conn from %s to %s (thread %u)",
		 sockaddr_to_str(&c->client_addr), sockaddr_to_str(taddr), w->idx);
	return 0;
}

static int give_client_fd_to_a_worker(struct server_ctx *ctx, int fd,
				      struct sockaddr_in46 *addr)
{
	struct client_state *c;
	struct server_wrk *w;
	int ret;

	w = pick_worker_for_new_conn(ctx);
	c = get_free_client_slot(w);
	if (!c) {
		pr_error("No free client slots, closing connection... (thread %u)", w->idx);
		return 0;
	}

	c->client_fd = fd;
	c->client_addr = *addr;
	ret = prepare_target_connect(w, c);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	atomic_fetch_add(&w->nr_active_clients, 1u);
	return 0;
}

static int handle_accept_event(struct server_wrk *w)
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
	ret = give_client_fd_to_a_worker(ctx, fd, &addr);
	if (ret) {
		close(fd);
		return ret;
	}

	return 0;
}

static int handle_target_connect_event(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	uint32_t events = ev->events;
	union epoll_data data;
	socklen_t len;
	int ret, tmp;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_error("Target connect failed: %s (thread %u)", strerror(errno), w->idx);
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
	data.u64 |= EPOLL_TARGET_EVENT_MASK;
	c->tpoll_mask = EPOLLIN;
	ret = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	data.ptr = c;
	data.u64 |= EPOLL_CLIENT_EVENT_MASK;
	c->cpoll_mask = EPOLLIN;
	ret = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
	if (ret) {
		put_client_slot(w, c);
		return ret;
	}

	c->cbuf = malloc(SPLICE_BUF_SIZE);
	c->tbuf = malloc(SPLICE_BUF_SIZE);
	if (unlikely(!c->cbuf || !c->tbuf)) {
		pr_error("Failed to allocate splice buffers: %s (thread %u)", strerror(errno), w->idx);
		put_client_slot(w, c);
		return -ENOMEM;
	}

	c->cbuf_len = 0;
	c->tbuf_len = 0;
	pr_debug("Forward connection established from %s to %s (thread %u)",
		 sockaddr_to_str(&c->client_addr),
		 sockaddr_to_str(&w->ctx->cfg.target_addr), w->idx);

	return 0;
}

struct splice_buf {
	char *buf;
	size_t cur_len;
	size_t max_len;
};

static ssize_t do_splice(int src_fd, int dst_fd, struct splice_buf *sb)
{
	size_t recv_len;
	ssize_t ret;

	recv_len = sb->max_len - sb->cur_len;
	if (recv_len > 0) {
		ret = recv(src_fd, sb->buf + sb->cur_len, recv_len, MSG_DONTWAIT);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN)
				goto do_send;

			pr_errorv("Failed to read from FD %d: %s", src_fd, strerror(ret));
			return -ret;
		}

		if (ret == 0)
			return -EIO;

		sb->cur_len += (size_t)ret;
	}

do_send:
	if (sb->cur_len == 0)
		return 0;

	ret = send(dst_fd, sb->buf, sb->cur_len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_errorv("Failed to write to FD %d: %s", dst_fd, strerror(ret));
		return -ret;
	}

	if (ret == 0)
		return -EIO;

	sb->cur_len -= (size_t)ret;
	if (sb->cur_len > 0)
		memmove(sb->buf, sb->buf + ret, sb->cur_len);

	return ret;
}

static int handle_target_event(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	uint32_t events = ev->events;
	union epoll_data data;
	struct splice_buf sb;
	ssize_t ret;
	int err;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("Target socket hit (EPOLLERR|EPOLLHUP): %s (thread %u)", strerror(errno), w->idx);
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		sb.buf = c->tbuf;
		sb.cur_len = c->tbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		ret = do_splice(c->target_fd, c->client_fd, &sb);
		if (ret < 0) {
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
			data.u64 |= EPOLL_CLIENT_EVENT_MASK;
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
			data.u64 |= EPOLL_TARGET_EVENT_MASK;
			c->tpoll_mask &= ~EPOLLIN;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}
	}

	if (events & EPOLLOUT) {
		sb.buf = c->cbuf;
		sb.cur_len = c->cbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		ret = do_splice(c->client_fd, c->target_fd, &sb);
		if (ret < 0) {
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
			data.u64 |= EPOLL_TARGET_EVENT_MASK;
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
			data.u64 |= EPOLL_CLIENT_EVENT_MASK;
			c->cpoll_mask |= EPOLLIN;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}
	}

	return 0;
}

static int handle_client_event(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = ev->data.ptr;
	uint32_t events = ev->events;
	union epoll_data data;
	struct splice_buf sb;
	ssize_t ret;
	int err;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("Client socket hit (EPOLLERR|EPOLLHUP): %s (thread %u)", strerror(errno), w->idx);
		put_client_slot(w, c);
		return 0;
	}

	if (events & EPOLLIN) {
		sb.buf = c->cbuf;
		sb.cur_len = c->cbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		ret = do_splice(c->client_fd, c->target_fd, &sb);
		if (ret < 0) {
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
			data.u64 |= EPOLL_TARGET_EVENT_MASK;
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
			data.u64 |= EPOLL_CLIENT_EVENT_MASK;
			c->cpoll_mask &= ~EPOLLIN;
			err = epoll_mod(w, c->client_fd, c->cpoll_mask, data);
			assert(!err);
		}
	}

	if (events & EPOLLOUT) {
		sb.buf = c->tbuf;
		sb.cur_len = c->tbuf_len;
		sb.max_len = SPLICE_BUF_SIZE;
		ret = do_splice(c->target_fd, c->client_fd, &sb);
		if (ret < 0) {
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
			data.u64 |= EPOLL_CLIENT_EVENT_MASK;
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
			data.u64 |= EPOLL_TARGET_EVENT_MASK;
			c->tpoll_mask |= EPOLLIN;
			err = epoll_mod(w, c->target_fd, c->tpoll_mask, data);
			assert(!err);
		}
	}

	return 0;
}

static int handle_event(struct server_wrk *w, struct epoll_event *ev)
{
	uint64_t mask;

	if (ev->data.u64 == EPOLL_EV_FD_DATA)
		return consume_event_fd(w);

	if (ev->data.u64 == EPOLL_TCP_FD_DATA)
		return handle_accept_event(w);

	mask = ev->data.u64 & EPOLL_DATA_MASK;
	ev->data.u64 &= ~EPOLL_DATA_MASK;

	if (mask == EPOLL_TARGET_CONNECT_MASK)
		return handle_target_connect_event(w, ev);

	if (mask == EPOLL_TARGET_EVENT_MASK)
		return handle_target_event(w, ev);

	if (mask == EPOLL_CLIENT_EVENT_MASK)
		return handle_client_event(w, ev);

	return 0;
}

static int handle_events(struct server_wrk *w, int nr_events)
{
	int ret, i;

	for (i = 0; i < nr_events; i++) {
		if (w->handle_events_should_stop)
			break;

		ret = handle_event(w, &w->events[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static void *worker_func(void *data)
{
	struct server_wrk *w = data;
	struct server_ctx *ctx = w->ctx;
	int ret = 0;

	pr_info("Worker thread %u started", w->idx);
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
