
#define USE_CLIENT_SPEEDMGR_QUOTA
#define DONT_USE_INTERNAL_SPEEDMGR_QUOTA
#include "quota.h"
#include "quota.c"

#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void)
{
	struct quota_pkt_res res;
	struct qo_cl *qc;
	int ret;

	ret = qo_cl_init(&qc, "./q.sock", 1000);
	if (ret < 0) {
		printf("qo_cl_init failed: %s\n", strerror(-ret));
		return ret;
	}

	ret = qo_cl_do_cmd(qc, QUOTA_PKT_CMD_GET, 0, &res);
	if (ret < 0) {
		printf("qo_cl_do_cmd failed: %s\n", strerror(-ret));
		qo_cl_close(qc);
		return ret;
	}

	printf("enabled: %d, exceeded: %d, before: %lld, after: %lld\n",
		res.enabled, res.exceeded, res.ba.before, res.ba.after);

	qo_cl_close(qc);
	return 0;	
}
