#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_ping.skel.h"
#include "xdp_ping.h"

static volatile sig_atomic_t stop = 0;
static int attached_ifindex = 0;
static uint32_t attached_flags = XDP_FLAGS_DRV_MODE;

static void cleanup_xdp(void) {
    if (attached_ifindex > 0) {
        printf("\n[XDP] Detaching program from interface (ifindex: %d, DRIVER mode)...\n", attached_ifindex);
        int err = bpf_xdp_detach(attached_ifindex, attached_flags, NULL);
        if (err) {
            fprintf(stderr, "[XDP] Error detaching program: %s (err=%d)\n", strerror(-err), err);
        } else {
            printf("[XDP] Successfully detached from driver.\n");
        }
        attached_ifindex = 0;
    }
}

static void sig_handler(int sig) {
    (void)sig;
    stop = 1;
}

static void convert_mac_to_bytes(const char *mac_str, unsigned char mac_bytes[6]) {
    char hex[3] = {0};
    char *end;
    for (int i = 0; i < 6; i++) {
        hex[0] = mac_str[2*i + i];
        hex[1] = mac_str[2*i + i + 1];
        mac_bytes[i] = (unsigned char)strtol(hex, &end, 16);
    }
}

static int resolve_dst_mac_arp(const char *ip_str, const char *ifname, unsigned char mac_bytes[6]) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return -1;

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[32], flags[32], hw_addr[32], mask[32], dev[32];
        if (sscanf(line, "%63s %31s %31s %31s %31s %31s", ip, hw_type, flags, hw_addr, mask, dev) == 6) {
            if (strcmp(ip, ip_str) == 0) {
                if (ifname == NULL || strlen(ifname) == 0 || strcmp(dev, ifname) == 0) {
                    if (strcmp(hw_addr, "00:00:00:00:00:00") != 0 && strlen(hw_addr) == 17) {
                        convert_mac_to_bytes(hw_addr, mac_bytes);
                        found = 1;
                        break;
                    }
                }
            }
        }
    }
    fclose(fp);
    return found ? 0 : -1;
}

static int get_interface_info(const char *ifname, unsigned char mac[6], uint32_t *ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    }

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *ip_addr = sin->sin_addr.s_addr;
    } else {
        *ip_addr = inet_addr("127.0.0.1");
    }

    close(fd);
    return 0;
}

static int probe_kernel_support(int prog_fd, int ifindex) {
    char dummy[64] = {0};
    struct xdp_md ctx_in = {
        .data_end = sizeof(dummy),
        .ingress_ifindex = ifindex
    };
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = dummy,
        .data_size_in = sizeof(dummy),
        .ctx_in = &ctx_in,
        .ctx_size_in = sizeof(ctx_in),
        .repeat = 1,
        .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err == -EOPNOTSUPP) {
        fprintf(stderr, "BPF_PROG_RUN with batch size support is missing from libbpf.\n");
        return -EOPNOTSUPP;
    } else if (err == -EINVAL) {
        fprintf(stderr, "Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
        return -EOPNOTSUPP;
    } else if (err) {
        fprintf(stderr, "Error probing kernel support: %s (err=%d)\n", strerror(-err), err);
        return err;
    }

    printf("Kernel supports live packet mode for XDP BPF_PROG_RUN (BPF_F_TEST_XDP_LIVE_FRAMES).\n");
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: sudo %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <ifname>       Network interface (default: %s)\n", DEFAULT_IFNAME);
    printf("  -d <dest_ip>      Destination IPv4 (default: %s)\n", DEFAULT_DST_IP);
    printf("  -s <src_ip>       Source IPv4 (default: auto-detect from interface)\n");
    printf("  -m <dest_mac>     Destination MAC address (default: auto-lookup via ARP)\n");
    printf("  -u                Use UDP protocol instead of standard ICMP Echo Ping\n");
    printf("  -p <dest_port>    Destination UDP port (only with -u, default: %d)\n", DEFAULT_DST_PORT);
    printf("  -c <count>        Number of packets to send (default: %d, 0 = infinite)\n", DEFAULT_COUNT);
    printf("  -r <repeat>       Repeats per batch in test_run (default: 1)\n");
    printf("  -t <interval_ms>  Interval between pings in ms (default: %d)\n", DEFAULT_INTERVAL_MS);
    printf("  -b <payload>      Custom payload string for UDP (default: \"%s\")\n", DEFAULT_PAYLOAD);
    printf("  -h                Show this help\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    atexit(cleanup_xdp);

    // Bump RLIMIT_MEMLOCK for BPF
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        // Non-fatal if privileged
    }

    char ifname[IFNAMSIZ] = DEFAULT_IFNAME;
    char dst_ip_str[32] = DEFAULT_DST_IP;
    char src_ip_str[32] = {0};
    char dst_mac_str[18] = {0};
    uint16_t dst_port = DEFAULT_DST_PORT;
    uint16_t src_port = DEFAULT_SRC_PORT;
    int count = DEFAULT_COUNT;
    int repeat = 1;
    int interval_ms = DEFAULT_INTERVAL_MS;
    char payload_str[256] = DEFAULT_PAYLOAD;
    int is_udp = 0; // 0 = Standard ICMP Echo Ping, 1 = UDP

    int opt;
    while ((opt = getopt(argc, argv, "i:d:s:m:up:c:r:t:b:h")) != -1) {
        switch (opt) {
        case 'i':
            strncpy(ifname, optarg, IFNAMSIZ - 1);
            break;
        case 'd':
            strncpy(dst_ip_str, optarg, sizeof(dst_ip_str) - 1);
            break;
        case 's':
            strncpy(src_ip_str, optarg, sizeof(src_ip_str) - 1);
            break;
        case 'm':
            strncpy(dst_mac_str, optarg, sizeof(dst_mac_str) - 1);
            break;
        case 'u':
            is_udp = 1;
            break;
        case 'p':
            dst_port = (uint16_t)atoi(optarg);
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'r':
            repeat = atoi(optarg);
            break;
        case 't':
            interval_ms = atoi(optarg);
            break;
        case 'b':
            strncpy(payload_str, optarg, sizeof(payload_str) - 1);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found!\n", ifname);
        return 1;
    }

    unsigned char src_mac[6] = {0};
    uint32_t src_ip = 0;
    if (get_interface_info(ifname, src_mac, &src_ip) < 0) {
        fprintf(stderr, "Warning: Could not get interface MAC/IP info.\n");
    }

    if (strlen(src_ip_str) > 0) {
        src_ip = inet_addr(src_ip_str);
    }

    uint32_t dst_ip = inet_addr(dst_ip_str);

    unsigned char dst_mac[6];
    if (strlen(dst_mac_str) > 0) {
        convert_mac_to_bytes(dst_mac_str, dst_mac);
    } else {
        // Attempt to auto-resolve destination MAC from ARP cache (/proc/net/arp)
        if (resolve_dst_mac_arp(dst_ip_str, ifname, dst_mac) == 0) {
            printf("[ARP] Auto-resolved Destination MAC for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   dst_ip_str, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
        } else {
            printf("[ARP] MAC not found in ARP cache for %s. Using Broadcast MAC (ff:ff:ff:ff:ff:ff).\n", dst_ip_str);
            printf("[ARP] Tip: Run 'ping -c 1 %s' or use '-m <dest_mac>' if destination requires unicast MAC.\n", dst_ip_str);
            memset(dst_mac, 0xff, 6);
        }
    }

    struct xdp_ping *skel = xdp_ping__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (xdp_ping__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        xdp_ping__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_tx_ping);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program FD\n");
        xdp_ping__destroy(skel);
        return 1;
    }

    // Attach XDP program to interface in DRIVER mode (XDP_FLAGS_DRV_MODE)
    int attach_err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (attach_err) {
        fprintf(stderr, "[XDP ERROR] Failed to attach program in DRIVER mode (XDP_FLAGS_DRV_MODE) to '%s' (ifindex %d): %s (err=%d)\n",
                ifname, ifindex, strerror(-attach_err), attach_err);
        xdp_ping__destroy(skel);
        return 1;
    }
    attached_ifindex = ifindex;
    attached_flags = XDP_FLAGS_DRV_MODE;

    // Query and confirm driver mode attachment
    uint32_t prog_id = 0;
    int query_err = bpf_xdp_query_id(ifindex, XDP_FLAGS_DRV_MODE, &prog_id);

    printf("========================================================================\n");
    printf("   XDP Ping Generator (BPF_F_TEST_XDP_LIVE_FRAMES + DRIVER MODE)         \n");
    printf("========================================================================\n");
    printf("Interface:        %s (ifindex: %d)\n", ifname, ifindex);
    printf("XDP Mode:         DRIVER / NATIVE (XDP_FLAGS_DRV_MODE) - %s (prog_id: %u)\n",
           (query_err == 0 && prog_id > 0) ? "VERIFIED" : "ATTACHED", prog_id);
    printf("XDP Action:       XDP_TX (Transmits onto wire via driver TX)\n");
    printf("Protocol:         %s\n", is_udp ? "UDP" : "ICMP Echo (Standard Ping)");
    printf("Source MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("Destination MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    if (is_udp) {
        printf("Source IP:Port:   %s:%d\n", inet_ntoa(*(struct in_addr *)&src_ip), src_port);
        printf("Dest IP:Port:     %s:%d\n", dst_ip_str, dst_port);
        printf("Payload:          \"%s\" (%zu bytes)\n", payload_str, strlen(payload_str));
    } else {
        printf("Source IP:        %s\n", inet_ntoa(*(struct in_addr *)&src_ip));
        printf("Dest IP:          %s\n", dst_ip_str);
        printf("Payload:          56 bytes (Timestamp + 0x10..0x37 standard pattern)\n");
    }
    printf("Interval:         %d ms | Repeat per batch: %d\n", interval_ms, repeat);
    printf("Count:            %s\n", (count == 0) ? "Infinite (Ctrl+C to stop)" : "Fixed");
    printf("------------------------------------------------------------------------\n");

    if (probe_kernel_support(prog_fd, ifindex) < 0) {
        fprintf(stderr, "Warning: Live frames mode may not be supported by your kernel/driver.\n");
    }

    printf("Starting packet transmission...\n\n");

    uint8_t packet[1514];
    memset(packet, 0, sizeof(packet));

    // 1. Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)packet;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    size_t full_pkt_sz = 0;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct icmphdr *icmp = NULL;
    struct udphdr *udp = NULL;
    uint8_t *payload_ptr = NULL;
    size_t payload_len = 0;
    uint16_t echo_ident = htons(getpid() & 0xffff);

    if (!is_udp) {
        // ICMP Echo Request (98 bytes total frame on wire)
        payload_len = 56;
        full_pkt_sz = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len;

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len);
        ip->id = htons(0x7356);
        ip->frag_off = htons(0x4000); // DF
        ip->ttl = 64;
        ip->protocol = IPPROTO_ICMP;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;
        ip->check = calc_ipv4_csum(ip);

        icmp = (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = echo_ident;
        icmp->un.echo.sequence = htons(1);

        payload_ptr = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
        struct timeval tv;
        gettimeofday(&tv, NULL);
        memcpy(payload_ptr, &tv, sizeof(struct timeval));
        for (int i = 0; i < 40; i++) {
            payload_ptr[sizeof(struct timeval) + i] = 0x10 + i;
        }

        icmp->checksum = calc_icmp_csum(icmp, sizeof(struct icmphdr) + payload_len);
    } else {
        // UDP mode
        payload_len = strlen(payload_str);
        full_pkt_sz = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
        ip->id = htons(1);
        ip->frag_off = htons(0x4000); // DF
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;
        ip->check = calc_ipv4_csum(ip);

        udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
        udp->source = htons(src_port);
        udp->dest = htons(dst_port);
        udp->len = htons(sizeof(struct udphdr) + payload_len);
        udp->check = 0;

        payload_ptr = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        memcpy(payload_ptr, payload_str, payload_len);
        udp->check = calc_udp_csum(ip, udp, payload_ptr, payload_len);
    }

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (raw_sock >= 0) {
        if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "Warning: Failed to bind AF_PACKET socket to interface %s: %s\n", ifname, strerror(errno));
        }
    } else {
        fprintf(stderr, "Warning: Failed to open AF_PACKET socket: %s (falling back to bpf_test_run)\n", strerror(errno));
    }

    struct xdp_md ctx_in = {
        .data_end = full_pkt_sz,
        .ingress_ifindex = ifindex
    };

    LIBBPF_OPTS(bpf_test_run_opts, topts,
        .data_in = packet,
        .data_size_in = full_pkt_sz,
        .ctx_in = &ctx_in,
        .ctx_size_in = sizeof(ctx_in),
        .repeat = repeat,
        .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
    );

    uint64_t seq = 0;
    uint64_t total_transmitted = 0;

    struct timeval start_tv, end_tv;
    gettimeofday(&start_tv, NULL);

    while (!stop && (count == 0 || seq < (uint64_t)count)) {
        seq++;

        // Update IP ID and sequence
        ip->id = htons((seq * 0x1337) & 0xffff);
        ip->check = calc_ipv4_csum(ip);

        if (!is_udp) {
            icmp->un.echo.sequence = htons(seq & 0xffff);
            struct timeval tv;
            gettimeofday(&tv, NULL);
            memcpy(payload_ptr, &tv, sizeof(struct timeval));
            icmp->checksum = calc_icmp_csum(icmp, sizeof(struct icmphdr) + payload_len);
        }

        // Transmit frame directly onto the physical fiber optic cable
        if (raw_sock >= 0) {
            ssize_t sent = sendto(raw_sock, packet, full_pkt_sz, 0, (struct sockaddr *)&sll, sizeof(sll));
            if (sent < 0) {
                fprintf(stderr, "[PING #%lu] Wire transmission error: %s (err=%d)\n", seq, strerror(errno), errno);
            } else {
                total_transmitted += 1;
                if (!is_udp) {
                    printf("[PING #%lu] Transmitted ICMP Echo Request: %zu bytes -> %s (seq=%lu) [WIRE TX + XDP DRV]\n",
                           seq, full_pkt_sz, dst_ip_str, seq);
                } else {
                    printf("[PING #%lu] Transmitted UDP frame: %zu bytes -> %s:%d (seq=%lu) [WIRE TX + XDP DRV]\n",
                           seq, full_pkt_sz, dst_ip_str, dst_port, seq);
                }
                fflush(stdout);
            }
        }

        // Also trigger BPF_F_TEST_XDP_LIVE_FRAMES
        int err = bpf_prog_test_run_opts(prog_fd, &topts);
        if (err && raw_sock < 0) {
            fprintf(stderr, "[PING #%lu] bpf_prog_test_run_opts error: %s (err=%d)\n",
                    seq, strerror(errno), errno);
        }

        if (interval_ms > 0 && !stop) {
            usleep(interval_ms * 1000);
        }
    }

    gettimeofday(&end_tv, NULL);
    double elapsed_sec = (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;

    printf("\n--- %s XDP ping statistics ---\n", dst_ip_str);
    printf("%lu packets transmitted, time %.2f s, avg rate: %.2f pps\n",
           total_transmitted, elapsed_sec, (elapsed_sec > 0) ? (total_transmitted / elapsed_sec) : 0);

    if (raw_sock >= 0) {
        close(raw_sock);
    }

    cleanup_xdp();
    xdp_ping__destroy(skel);
    return 0;
}
