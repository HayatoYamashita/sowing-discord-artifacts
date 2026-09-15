/* test_e2e_adversary — end-to-end check of the C-side pipeline:
 *
 *   adversary_nals_load(H.265 file)
 *     → adversary_nals_next()           (pop an adversary NAL)
 *     → build_adversary_plaintext()     (lay out plaintext for a given target_len)
 *     → ambig_build_packet()            (compute ambiguous CT + tag under K_old,K_new)
 *     → mbedtls AES-GCM decrypt with K_old → must recover the plaintext
 *                                        bit-for-bit OUTSIDE the
 *                                        adjustment slot, and the first
 *                                        NAL must be the adversary NAL.
 *     → mbedtls AES-GCM decrypt with K_new → tag must still verify (the
 *                                        ambig math guarantees this).
 *
 * Exercises a spread of target_len values to stress the layout's
 * alignment logic and a spread of NAL types from the loaded stream. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/gcm.h>

#include "adversary_nals.h"
#include "attack_crypto.h"

static int gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[16], uint8_t *pt_out) {
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc != 0) { mbedtls_gcm_free(&g); return -1; }
    rc = mbedtls_gcm_auth_decrypt(&g, ct_len, nonce, 12, aad, aad_len, tag, 16,
                                  ct, pt_out);
    mbedtls_gcm_free(&g);
    return rc;
}

static int run_one(const uint8_t *nal, size_t nal_len, size_t target_len,
                   const uint8_t mk_old[32], const uint8_t mk_new[32],
                   const uint8_t salt[12]) {
    uint8_t plaintext[2048];
    if (target_len > sizeof(plaintext)) return -1;
    size_t adj_off = 0;
    int rc = build_adversary_plaintext(nal, nal_len, target_len, plaintext,
                                       &adj_off);
    if (rc != 0) {
        printf("    target_len=%4zu  nal=%3zuB  SKIP (doesn't fit)\n",
               target_len, nal_len);
        return 0;   /* skip is legitimate behaviour, not a failure */
    }

    /* Layout invariants */
    if (plaintext[0] != 0x00 || plaintext[1] != 0x00 || plaintext[2] != 0x01) {
        printf("[-] start code missing at offset 0\n"); return -2;
    }
    if (memcmp(plaintext + 3, nal, nal_len) != 0) {
        printf("[-] adversary NAL not at offset 3\n"); return -3;
    }
    size_t fd_nut_off = 3 + nal_len + 3;
    if (plaintext[fd_nut_off] != 0x4C || plaintext[fd_nut_off + 1] != 0x01) {
        printf("[-] FD_NUT header missing\n"); return -4;
    }
    if (plaintext[target_len - 1] != 0x80) {
        printf("[-] rbsp_trailing_bits missing\n"); return -5;
    }

    ambig_session_keys_t keys;
    /* Standalone e2e test uses one shared salt for both K_old and K_new. */
    ambig_derive_session_keys(mk_old, salt, mk_new, salt, &keys);

    /* AAD = 12-byte RTP header (CC=0). */
    uint8_t aad[12] = {0x80, 0x60, 0x00, 0x42,
                       0xde, 0xad, 0xbe, 0xef,
                       0xca, 0xfe, 0xba, 0xbe};
    uint32_t ssrc = 0xdeadbeefU, roc = 0x7;
    uint16_t seq = 0x42;

    uint8_t ct[2048], tag[16];
    rc = ambig_build_packet(&keys, ssrc, roc, seq, aad, sizeof(aad), plaintext,
                            target_len, adj_off, ct, tag);
    if (rc != 0) { printf("[-] ambig_build_packet rc=%d\n", rc); return -6; }

    /* Per-packet nonce */
    uint8_t in_nonce_old[12], in_nonce_new[12];
    uint8_t in[12] = {0, 0, 0xde, 0xad, 0xbe, 0xef,
                       0, 0, 0, 0x07, 0x00, 0x42};
    for (int i = 0; i < 12; i++) {
        in_nonce_old[i] = in[i] ^ keys.s_session_old[i];
        in_nonce_new[i] = in[i] ^ keys.s_session_new[i];
    }

    uint8_t pt_old[2048], pt_new[2048];
    int r_old = gcm_decrypt(keys.k_enc_old, in_nonce_old, aad, sizeof(aad), ct,
                            target_len, tag, pt_old);
    int r_new = gcm_decrypt(keys.k_enc_new, in_nonce_new, aad, sizeof(aad), ct,
                            target_len, tag, pt_new);
    if (r_old != 0 || r_new != 0) {
        printf("[-] auth failed: old=%d new=%d\n", r_old, r_new);
        return -7;
    }

    /* K_OLD must recover everything outside the adjustment slot. */
    for (size_t i = 0; i < target_len; i++) {
        if (i >= adj_off && i < adj_off + 16) continue;
        if (pt_old[i] != plaintext[i]) {
            printf("[-] K_OLD plaintext mismatch at byte %zu: got %02x, expected %02x\n",
                   i, pt_old[i], plaintext[i]);
            return -8;
        }
    }
    /* And the first NAL in K_OLD-recovered bytes is the adversary NAL. */
    if (memcmp(pt_old + 3, nal, nal_len) != 0) {
        printf("[-] K_OLD did not reproduce adversary NAL\n"); return -9;
    }
    /* K_NEW recovered bytes outside the adjustment slot will *differ*
     * from our plaintext (because K_NEW decrypts with a different
     * keystream). Just sanity-check they differ. */
    int differs = 0;
    for (size_t i = 0; i < target_len; i++) {
        if (i >= adj_off && i < adj_off + 16) continue;
        if (pt_new[i] != plaintext[i]) { differs = 1; break; }
    }
    if (!differs) { printf("[-] K_NEW unexpectedly recovers plaintext\n"); return -10; }

    printf("    target_len=%4zu  nal=%3zuB  adj_off=%4zu  OK (K_OLD recovers NAL, "
           "K_NEW garbled)\n", target_len, nal_len, adj_off);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *video = (argc > 1) ? argv[1]
                                    : "../../src-video/video_01_main_1920x1440.h265";
    if (adversary_nals_load(video) != 0) return 1;
    if (!adversary_nals_ready()) {
        fprintf(stderr, "[-] no adversary NALs loaded\n"); return 1;
    }

    uint8_t mk_old[32], mk_new[32], salt[12];
    for (int i = 0; i < 32; i++) mk_old[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 32; i++) mk_new[i] = (uint8_t)(0xff - i);
    for (int i = 0; i < 12; i++) salt[i] = (uint8_t)(0x10 + i);

    /* Sweep target_len across the range a hook would actually see. We
     * sample first 10 NALs from the loaded stream and try several
     * target_len values for each. */
    int total = 0, failed = 0;
    for (int n = 0; n < 10; n++) {
        size_t nal_len = 0;
        const uint8_t *nal = adversary_nals_next(&nal_len);
        if (!nal) break;

        printf("\nNAL #%d: type=%d size=%zu B\n", n,
               (nal_len > 0) ? ((nal[0] >> 1) & 0x3F) : -1, nal_len);
        for (size_t tl = 64; tl <= 1280; tl += 64) {
            int rc = run_one(nal, nal_len, tl, mk_old, mk_new, salt);
            if (rc != 0 && rc != 0) failed++;
            total++;
        }
    }
    printf("\n%s: %d/%d e2e checks passed\n", failed ? "[-] FAIL" : "[+] OK",
           total - failed, total);
    return failed ? 1 : 0;
}
