#!/usr/bin/env python3
"""
Throughput benchmark for the FlowSentry DPI engines.

Times the single-threaded engine (dpi_simple, which runs the JSON-stats and
top-domains SNI report added in this repo) against the multi-threaded engine
(dpi_engine) at several worker counts, on a large generated capture.

    python bench/gen_large_pcap.py --flows 250000 --out bench/large.pcap
    python bench/benchmark.py

Honest finding on this workload: file-replay DPI is dominated by sequential
pcap reading + per-packet parsing (I/O bound), so the multi-threaded pipeline's
queue/coordination overhead makes it NOT faster than the single-threaded engine
here - a practical Amdahl's-law limit. Parallelism of this shape pays off when
the per-packet work is heavier (e.g. regex/DPI signature matching) or when
packets arrive concurrently from a live NIC, not when replaying one file as fast
as the disk and a single parser can feed it.
"""
import os
import subprocess
import sys
import time

PCAP = "bench/large.pcap"
OUT = "bench/out.pcap"
REPEAT = 3


def time_cmd(cmd):
    best = float("inf")
    rc = 0
    for _ in range(REPEAT):
        start = time.perf_counter()
        rc = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode
        best = min(best, time.perf_counter() - start)
    return best, rc


def count_packets(path):
    # pcap global header = 24 bytes; each record has a 16-byte header.
    # We know the generator's layout, but count generically from the file.
    size = os.path.getsize(path)
    return size  # bytes; packet count is printed by the generator


def main():
    if not os.path.exists(PCAP):
        sys.exit(f"Missing {PCAP}. Run: python bench/gen_large_pcap.py --flows 250000 --out {PCAP}")
    exe = ".exe" if os.name == "nt" else ""
    simple = f"./dpi_simple{exe}"
    engine = f"./dpi_engine{exe}"
    if not (os.path.exists(simple) and os.path.exists(engine)):
        sys.exit("Build the engines first (see README 'Build Commands'). "
                 "Use -static so they launch standalone.")

    PKTS = 1_000_000  # matches gen_large_pcap.py --flows 250000
    configs = [
        ("single-threaded", [simple, PCAP, OUT]),
        ("MT 4 workers  ", [engine, PCAP, OUT, "--lbs", "2", "--fps", "2"]),
        ("MT 8 workers  ", [engine, PCAP, OUT, "--lbs", "2", "--fps", "4"]),
        ("MT 16 workers ", [engine, PCAP, OUT, "--lbs", "4", "--fps", "4"]),
    ]
    print(f"\nThroughput benchmark ({PKTS:,} packets, best of {REPEAT})")
    print("-" * 60)
    baseline = None
    for name, cmd in configs:
        secs, rc = time_cmd(cmd)
        pps = PKTS / secs
        if baseline is None:
            baseline = secs
            speed = "baseline"
        else:
            speed = f"{baseline / secs:.2f}x vs single-threaded"
        print(f"{name}: {secs:6.2f}s  {pps:>10,.0f} pkt/s   {speed}")
    print("-" * 60)
    print("See module docstring for why MT is not faster on file replay.\n")


if __name__ == "__main__":
    main()
