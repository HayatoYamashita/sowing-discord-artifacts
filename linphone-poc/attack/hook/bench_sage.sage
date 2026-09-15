"""Micro-benchmark for build_ambiguous_under_inner_keys() — the sage
reference implementation that attack_crypto.c is ported from. Mirrors
the C bench (bench_attack_crypto.c) so the two can be compared
side-by-side. Reports mean / p50 / p99 wall-time per call across the
same plaintext sizes."""

from binascii import unhexlify
import statistics
import time

load('attack/crypto/util.sage')
load('attack/crypto/gcm.sage')
load('attack/crypto/srtp_kdf.sage')
load('attack/crypto/test_packet_ambiguous.sage')


def bench_one(label, plaintext_len, iters):
    K_OLD = bytes(((i + 1) & 0xff) for i in range(32))
    K_NEW = bytes(((0xff - i) & 0xff) for i in range(32))
    SALT  = bytes(((0x10 + i) & 0xff) for i in range(12))
    AAD   = bytes.fromhex("80600042deadbeefcafebabe")
    PT    = bytes((i & 0xff) for i in range(plaintext_len))

    # Warmup
    for i in range(4):
        build_ambiguous_under_inner_keys(
            PT, K_OLD, K_NEW, SALT, 0xdeadbeef, 7, i & 0xffff,
            adjustment_block_offset=0, aad=AAD,
        )

    samples = []
    for i in range(iters):
        t0 = time.perf_counter_ns()
        build_ambiguous_under_inner_keys(
            PT, K_OLD, K_NEW, SALT, 0xdeadbeef, 7, i & 0xffff,
            adjustment_block_offset=0, aad=AAD,
        )
        t1 = time.perf_counter_ns()
        samples.append(t1 - t0)

    samples.sort()
    mean_us = statistics.mean(samples) / 1000.0
    p50_us  = samples[len(samples) // 2] / 1000.0
    p99_us  = samples[(len(samples) * 99) // 100] / 1000.0
    pmin_us = samples[0] / 1000.0
    print(f"  {label:26s}  iters={iters}  mean={mean_us:8.1f} us  "
          f"p50={p50_us:8.1f} us  p99={p99_us:8.1f} us  min={pmin_us:8.1f} us  "
          f"(throughput≈{1e6/mean_us:8.1f} calls/s)")


def bench_derive(iters):
    K_OLD = bytes(((i + 1) & 0xff) for i in range(32))
    K_NEW = bytes(((0xff - i) & 0xff) for i in range(32))
    SALT  = bytes(((0x10 + i) & 0xff) for i in range(12))

    # Warmup
    for _ in range(4):
        derive_inner_keys(K_OLD, SALT)
        derive_inner_keys(K_NEW, SALT)

    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        derive_inner_keys(K_OLD, SALT)
        derive_inner_keys(K_NEW, SALT)
        t1 = time.perf_counter_ns()
        samples.append(t1 - t0)
    samples.sort()
    mean_us = statistics.mean(samples) / 1000.0
    p50_us  = samples[len(samples) // 2] / 1000.0
    p99_us  = samples[(len(samples) * 99) // 100] / 1000.0
    print(f"  {'derive_inner_keys (×2)':26s}  iters={iters}  "
          f"mean={mean_us:8.1f} us  p50={p50_us:8.1f} us  p99={p99_us:8.1f} us")


def main():
    print("[*] sage implementation (attack/crypto/test_packet_ambiguous.sage)")
    bench_derive(200)
    bench_one("plaintext=16 B   (1 block)",   16,   100)
    bench_one("plaintext=80 B   (5 blocks)",  80,   100)
    bench_one("plaintext=256 B  (16 blocks)", 256,  50)
    bench_one("plaintext=1280 B (80 blocks)", 1280, 20)


if __name__ == "__main__":
    main()
