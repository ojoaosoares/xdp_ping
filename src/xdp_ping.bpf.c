// SPDX-License-Identifier: MIT
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_tx_ping(struct xdp_md *ctx)
{
    /*
     * When attached to the interface in DRIVER mode (XDP_FLAGS_DRV_MODE)
     * and triggered via bpf_prog_test_run_opts with BPF_F_TEST_XDP_LIVE_FRAMES,
     * returning XDP_TX transmits the frame onto the physical wire via the driver.
     */
    return XDP_TX;
}



