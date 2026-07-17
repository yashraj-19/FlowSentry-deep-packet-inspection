#!/usr/bin/env python3
"""
Generate a large multi-flow PCAP for throughput benchmarking.

Reuses the packet builders from generate_test_pcap.py but emits many distinct
5-tuples (randomized src IP/port, rotating SNIs) so the flow tables, the
load-balancer's hash distribution, and the SNI extractor all get exercised.

    python bench/gen_large_pcap.py --flows 250000 --out bench/large.pcap

~250k TLS flows x 4 packets ~= 1M packets.
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import generate_test_pcap as g  # reuse the exact packet builders

SNIS = [
    "www.google.com", "www.youtube.com", "www.facebook.com", "www.instagram.com",
    "twitter.com", "www.amazon.com", "www.netflix.com", "github.com",
    "discord.com", "zoom.us", "web.telegram.org", "www.tiktok.com",
    "open.spotify.com", "www.cloudflare.com", "www.microsoft.com", "www.apple.com",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=250000)
    ap.add_argument("--out", default="bench/large.pcap")
    args = ap.parse_args()

    random.seed(42)  # deterministic file
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    w = g.PCAPWriter(args.out)
    user_mac, gw_mac = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"

    packets = 0
    for i in range(args.flows):
        sni = SNIS[i % len(SNIS)]
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        dst_ip = f"142.250.{random.randint(0,255)}.{random.randint(1,254)}"
        src_port = random.randint(49152, 65535)
        seq = random.randint(1, 1_000_000)

        eth_out = g.create_ethernet_header(user_mac, gw_mac)
        # SYN
        tcp = g.create_tcp_header(src_port, 443, seq, 0, 0x02)
        w.write_packet(eth_out + g.create_ip_header(src_ip, dst_ip, 6, len(tcp)) + tcp)
        # SYN-ACK (reverse direction)
        tcp = g.create_tcp_header(443, src_port, seq + 1000, seq + 1, 0x12)
        w.write_packet(g.create_ethernet_header(gw_mac, user_mac)
                       + g.create_ip_header(dst_ip, src_ip, 6, len(tcp)) + tcp)
        # ACK
        tcp = g.create_tcp_header(src_port, 443, seq + 1, seq + 1001, 0x10)
        w.write_packet(eth_out + g.create_ip_header(src_ip, dst_ip, 6, len(tcp)) + tcp)
        # TLS Client Hello with SNI
        tls = g.create_tls_client_hello(sni)
        tcp = g.create_tcp_header(src_port, 443, seq + 1, seq + 1001, 0x18)
        w.write_packet(eth_out + g.create_ip_header(src_ip, dst_ip, 6, len(tcp) + len(tls)) + tcp + tls)
        packets += 4

    w.close()
    size_mb = os.path.getsize(args.out) / (1024 * 1024)
    print(f"Wrote {args.out}: {packets:,} packets across {args.flows:,} flows ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
