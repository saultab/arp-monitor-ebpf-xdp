#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> /* Helpers to convert endiannes
							  * (e.g., bpf_ntohs())
							  */
#include <linux/if_ether.h> /* Definition of struct ethhdr */
#include "if_arp.h"			/* Definition of struct arphdr */
#include "common.h"			/* Definition of struct event*/
#include <string.h>

/* BPF ring buffer map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	/* Retrieve pointers to the begin and end of the packet buffer */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Interpret the first part of the packet as an ethernet header */
	struct ethhdr *eth = data;

	/* Every time we access the packet buffer the eBPF verifier requires us
	 * to explicitly check that the address we are accessing doesn't exceed
	 * the buffer limits
	 */
	if (data + sizeof(*eth) > data_end)
	{
		/* The packet is malformed, the XDP_DROP return code
		 * instructs the kernel to drop it
		 */
		return XDP_DROP;
	}

	/* Check if packet is ARP */
	if (eth->h_proto == bpf_ntohs(ETH_P_ARP))
	{
		struct arphdr *arp = (data + sizeof(*eth));

		if (data + sizeof(*eth) + sizeof(*arp) > data_end)
		{
			/* The packet is malformed, the XDP_DROP return code
			 * instructs the kernel to drop it
			 */
			return XDP_DROP;
		}

		/* Reserve the packet to the ring buffer */
		struct event *e;
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

		/* Can't happen */
		if (!e)
		{
			return XDP_PASS;
		}

		/* Copy fields from packet to the event struct */
		e->ar_op = bpf_ntohs(arp->ar_op);

		e->ar_sha[0] = arp->ar_sha[0];
		e->ar_sha[1] = arp->ar_sha[1];
		e->ar_sha[2] = arp->ar_sha[2];
		e->ar_sha[3] = arp->ar_sha[3];
		e->ar_sha[4] = arp->ar_sha[4];
		e->ar_sha[5] = arp->ar_sha[5];

		e->ar_sip[0] = arp->ar_sip[0];
		e->ar_sip[1] = arp->ar_sip[1];
		e->ar_sip[2] = arp->ar_sip[2];
		e->ar_sip[3] = arp->ar_sip[3];

		e->ar_tha[0] = arp->ar_tha[0];
		e->ar_tha[1] = arp->ar_tha[1];
		e->ar_tha[2] = arp->ar_tha[2];
		e->ar_tha[3] = arp->ar_tha[3];
		e->ar_tha[4] = arp->ar_tha[4];
		e->ar_tha[5] = arp->ar_tha[5];

		e->ar_tip[0] = arp->ar_tip[0];
		e->ar_tip[1] = arp->ar_tip[1];
		e->ar_tip[2] = arp->ar_tip[2];
		e->ar_tip[3] = arp->ar_tip[3];

		/* Submit the packet to the ring buffer */
		bpf_ringbuf_submit(e, 0);
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";