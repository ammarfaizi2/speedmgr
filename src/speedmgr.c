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

static volatile bool *g_stop;
static uint8_t g_verbose;

int main(int argc, char *argv[])
{
	return 0;
}
