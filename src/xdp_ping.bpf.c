// SPDX-License-Identifier: MIT
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_tx_ping(struct xdp_md *ctx)
{
    /*
     * When invoked via bpf_prog_test_run_opts with BPF_F_TEST_XDP_LIVE_FRAMES,
     * XDP_TX transmits the frame onto the wire via the interface specified in ingress_ifindex.
     */
    return XDP_TX;
}
