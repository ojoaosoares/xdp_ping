#ifndef XDP_PING_H
#define XDP_PING_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_link.h>

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES (1U << 1)
#endif

#define DEFAULT_IFNAME      "enp1s0np1"
#define DEFAULT_DST_IP      "192.168.0.2"
#define DEFAULT_DST_PORT    9999
#define DEFAULT_SRC_PORT    12345
#define DEFAULT_INTERVAL_MS 1000
#define DEFAULT_COUNT       10
#define DEFAULT_PAYLOAD     "PING from XDP BPF_TEST"

static inline uint16_t csum_fold_u16(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~((uint16_t)sum);
}

static inline uint16_t calc_csum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    return csum_fold_u16(sum);
}

static inline uint16_t calc_ipv4_csum(struct iphdr *ip) {
    ip->check = 0;
    return calc_csum(ip, sizeof(struct iphdr));
}

static inline uint16_t calc_icmp_csum(struct icmphdr *icmp, size_t total_icmp_len) {
    icmp->checksum = 0;
    return calc_csum(icmp, total_icmp_len);
}

static inline uint16_t calc_udp_csum(struct iphdr *ip, struct udphdr *udp, const uint8_t *payload, size_t payload_len) {
    uint32_t sum = 0;
    udp->check = 0;

    // IPv4 Pseudo-header
    sum += ip->saddr & 0xffff;
    sum += ip->saddr >> 16;
    sum += ip->daddr & 0xffff;
    sum += ip->daddr >> 16;
    sum += htons(IPPROTO_UDP);
    sum += udp->len;

    // UDP Header
    uint16_t *u_ptr = (uint16_t *)udp;
    for (size_t i = 0; i < (sizeof(struct udphdr) / 2); i++)
        sum += u_ptr[i];

    // Payload
    const uint16_t *p_ptr = (const uint16_t *)payload;
    size_t words = payload_len / 2;
    for (size_t i = 0; i < words; i++)
        sum += p_ptr[i];

    if (payload_len & 1) {
        sum += (uint16_t)payload[payload_len - 1];
    }

    uint16_t res = csum_fold_u16(sum);
    return res ? res : 0xffff;
}

#endif /* XDP_PING_H */
