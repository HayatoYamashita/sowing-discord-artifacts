/* bench_attack_crypto — micro-benchmark for ambig_build_packet(), the
 * inner loop of the Step 2.5e srtp_protect hook. Reports mean / p50 /
 * p99 wall-time per call across several plaintext sizes that span the
 * range of H.265 NAL sizes we expect on the wire (16 B-128 B-1280 B).
 *
 * Also breaks out the KDF + nonce derivation cost (called once per key
 * rotation, not per packet) and the per-packet body. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "attack_crypto.h"

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void bench(const char *label, size_t plaintext_len, size_t iters) {
    /* Fixed inputs (don't matter for timing, just need legal layout). */
    uint8_t mk_old[32], mk_new[32], salt[12];
    for (int i = 0; i < 32; i++) mk_old[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 32; i++) mk_new[i] = (uint8_t)(0xff - i);
    for (int i = 0; i < 12; i++) salt[i] = (uint8_t)(0x10 + i);

    ambig_session_keys_t keys;
    if (ambig_derive_session_keys(mk_old, salt, mk_new, salt, &keys) != 0) {
        fprintf(stderr, "[-] derive failed\n"); exit(1);
    }

    /* AAD = a 12 B RTP fixed header (CC=0). */
    uint8_t aad[12] = {0x80, 0x60, 0x00, 0x42,
                       0xde, 0xad, 0xbe, 0xef,
                       0xca, 0xfe, 0xba, 0xbe};

    uint8_t *plaintext = (uint8_t *)malloc(plaintext_len);
    uint8_t *ct        = (uint8_t *)malloc(plaintext_len);
    for (size_t i = 0; i < plaintext_len; i++) plaintext[i] = (uint8_t)(i & 0xff);
    uint8_t tag[16];

    size_t adj = 0;   /* adjustment slot at the front of the buffer */

    /* Warmup. */
    for (size_t i = 0; i < 16; i++) {
        ambig_build_packet(&keys, 0xdeadbeefU, 7, (uint16_t)i, aad, sizeof(aad),
                           plaintext, plaintext_len, adj, ct, tag);
    }

    /* Measurement. */
    uint64_t *samples = (uint64_t *)calloc(iters, sizeof(uint64_t));
    for (size_t i = 0; i < iters; i++) {
        uint64_t t0 = mono_ns();
        ambig_build_packet(&keys, 0xdeadbeefU, 7, (uint16_t)i, aad, sizeof(aad),
                           plaintext, plaintext_len, adj, ct, tag);
        uint64_t t1 = mono_ns();
        samples[i] = t1 - t0;
    }

    qsort(samples, iters, sizeof(uint64_t), cmp_u64);
    uint64_t sum = 0;
    for (size_t i = 0; i < iters; i++) sum += samples[i];
    uint64_t mean_ns = sum / iters;
    uint64_t p50 = samples[iters / 2];
    uint64_t p99 = samples[(iters * 99) / 100];
    uint64_t pmin = samples[0];

    printf("  %-26s  iters=%zu  mean=%6.1f us  p50=%6.1f us  "
           "p99=%6.1f us  min=%6.1f us  (throughput≈%6.0f calls/s)\n",
           label, iters,
           mean_ns / 1000.0, p50 / 1000.0, p99 / 1000.0, pmin / 1000.0,
           1e9 / (double)mean_ns);

    free(samples);
    free(plaintext);
    free(ct);
}

static void bench_derive(size_t iters) {
    uint8_t mk_old[32], mk_new[32], salt[12];
    for (int i = 0; i < 32; i++) mk_old[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 32; i++) mk_new[i] = (uint8_t)(0xff - i);
    for (int i = 0; i < 12; i++) salt[i] = (uint8_t)(0x10 + i);

    ambig_session_keys_t keys;
    for (size_t i = 0; i < 16; i++)
        ambig_derive_session_keys(mk_old, salt, mk_new, salt, &keys);

    uint64_t *samples = (uint64_t *)calloc(iters, sizeof(uint64_t));
    for (size_t i = 0; i < iters; i++) {
        uint64_t t0 = mono_ns();
        ambig_derive_session_keys(mk_old, salt, mk_new, salt, &keys);
        uint64_t t1 = mono_ns();
        samples[i] = t1 - t0;
    }
    qsort(samples, iters, sizeof(uint64_t), cmp_u64);
    uint64_t sum = 0;
    for (size_t i = 0; i < iters; i++) sum += samples[i];
    printf("  %-26s  iters=%zu  mean=%6.1f us  p50=%6.1f us  p99=%6.1f us\n",
           "ambig_derive_session_keys", iters,
           (sum / iters) / 1000.0,
           samples[iters / 2] / 1000.0,
           samples[(iters * 99) / 100] / 1000.0);
    free(samples);
}

int main(void) {
    printf("[*] C implementation (attack_crypto.c)\n");
    bench_derive(2000);
    /* The plaintext lengths cover the typical Linphone H.265 single-NAL
     * range: ~16 B (PPS-like), ~80 B (small slice), ~256 B (SPS/SEI),
     * ~1280 B (large NAL ~ MTU limit). All multiples of 16 since the
     * builder requires block alignment. */
    bench("plaintext=16 B   (1 block)",   16,   5000);
    bench("plaintext=80 B   (5 blocks)",  80,   5000);
    bench("plaintext=256 B  (16 blocks)", 256,  3000);
    bench("plaintext=1280 B (80 blocks)", 1280, 1000);
    printf("\n[!] For real-time use: Linphone H.265 video pushes ~30 RTP\n"
           "    packets/s on a typical send stream → < 35 ms / packet budget.\n");
    return 0;
}
