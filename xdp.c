#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#define bpf_memcpy __builtin_memcpy

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

// https://github.com/AirVantage/sbulb/blob/master/sbulb/bpf/checksum.c#L21
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result !
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void recalc_icmp_csum(struct icmphdr* hdr, __be32 old_value, __be32 new_value) {
    __u64 csum = hdr->checksum;
    update_csum(&csum, old_value, new_value);
    hdr->checksum = csum;
}

__attribute__((__always_inline__))
static inline void recalc_ip_csum(struct iphdr* hdr, __be32 old_value, __be32 new_value) {
    __u64 csum = hdr->check;
    update_csum(&csum, old_value, new_value);
    hdr->check = csum;
}

SEC("xdp")
int pinger(struct xdp_md* ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    struct icmphdr* icmphdr = (void*)(iph + 1);
    if ((void*)(icmphdr + 1) > data_end) {
        return XDP_PASS;
    }

    if (icmphdr->type != 8) {
        return XDP_PASS;
    }

    __u8 tmp_mac[ETH_ALEN];
    bpf_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    bpf_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    bpf_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    __u32 tmp_ip = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = tmp_ip;

    icmphdr->type = 0;
    recalc_icmp_csum(icmphdr, 8, icmphdr->type);

    __u64* ts_secs = (void*)(icmphdr + 1);
    __u8* payload = (void*)(icmphdr + 1);
    int is_bsd = 0;
    if ((void*)(payload + 16) <= data_end) {
        // Check for BSD ping signature: 0x08, 0x09, 0x0a, 0x0b, ...
        if (payload[8] == 0x08 && payload[9] == 0x09 && payload[10] == 0x0a && payload[11] == 0x0b &&
            payload[12] == 0x0c && payload[13] == 0x0d && payload[14] == 0x0e && payload[15] == 0x0f) {
            is_bsd = 1;
        }
    }
    if ((void*)(ts_secs + 1) <= data_end) {
        __u64 old_secs = *ts_secs;
        *ts_secs -= bpf_get_prandom_u32() % 500;
        recalc_icmp_csum(icmphdr, old_secs, *ts_secs);
    }
    if (!is_bsd) {
        __u64* ts_nsecs = (void*)(icmphdr + 1) + sizeof(__u64);
        if ((void*)ts_nsecs + sizeof(__u64) <= data_end) {
            __u64 old_nsecs = *ts_nsecs;
            *ts_nsecs -= bpf_get_prandom_u32();
            recalc_icmp_csum(icmphdr, old_nsecs, *ts_nsecs);
        }
    }

    __u8 old_ttl = iph->ttl;
    iph->ttl = bpf_get_prandom_u32() % 200 + 40;
    recalc_ip_csum(iph, old_ttl, iph->ttl);

    __be16 old_seq = icmphdr->un.echo.sequence;
    icmphdr->un.echo.sequence = bpf_htons(bpf_get_prandom_u32() % 1000);
    recalc_icmp_csum(icmphdr, old_seq, icmphdr->un.echo.sequence);

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";

