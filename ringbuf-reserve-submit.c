#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "ringbuf-reserve-submit.skel.h"
#include "common.h"
#include "if_arp.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static char *opcode_to_text(__u16 opcode)
{
	switch (opcode)
	{
	case ARPOP_REQUEST:
		return "Request";
	case ARPOP_REPLY:
		return "Reply";
	default:
		return "Unknown";
	}
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s\t", ts);
    printf("%s\t\t", opcode_to_text(e->ar_op));
    printf("%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_sha[0], e->ar_sha[1], e->ar_sha[2], e->ar_sha[3], e->ar_sha[4], e->ar_sha[5]);
    printf("%d.%d.%d.%d\t\t", e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\t", e->ar_tha[0], e->ar_tha[1], e->ar_tha[2], e->ar_tha[3], e->ar_tha[4], e->ar_tha[5]);
    printf("%d.%d.%d.%d\n", e->ar_tip[0], e->ar_tip[1], e->ar_tip[2], e->ar_tip[3]);

	return 0;
}

int main(int argc, char **argv)
{
	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Setup interface */
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return -1;
	}

	unsigned ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0)
	{
		fprintf(stderr, "Unable to find interface %s\n", argv[1]);
		return -1;
	}

	/* Load and verify BPF application */
	struct ringbuf_reserve_submit_bpf *skel = NULL;
	skel = ringbuf_reserve_submit_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	int err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_prog), 0, 0);
	if (err)
	{
		fprintf(stderr, "Failed to attach XDP program: %s\n",
				strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please Ctrl+C to stop.\n");

    /* Process events */
    printf("%s\t\t%s\t\t%s\t\t%s\t\t%s\t\t%s\n",
           "TIME", "TYPE", "SENDER MAC", "SENDER IP", "TARGET MAC", "TARGET IP");

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Detach xdp program */
	bpf_xdp_detach(ifindex, 0, 0);

	/* Free resources */
	ring_buffer__free(rb);
	ringbuf_reserve_submit_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}