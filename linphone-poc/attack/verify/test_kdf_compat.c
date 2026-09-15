/*
 * test_kdf_compat.c — Bit-for-bit compatibility check between our
 * attack/crypto/srtp_kdf.sage and libsrtp 2.7.0's internal SRTP-KDF.
 *
 * Why this matters: in Step 2.1 we built `srtp_kdf()` in Sage that
 * derives K_enc and S_session from (inner_master_key_sender, CSPI[:14])
 * exactly the way Linphone's inner-encryption layer does (paper App. C
 * eq. 14-17, which cites libsrtp 2.7.0). For Step 2.x we have to be
 * sure our reference implementation gives the same bytes libsrtp would
 * give on the wire, otherwise the ambiguous ciphertext won't actually
 * authenticate.
 *
 * SRTP-KDF is internally just AES-CM with a specific IV constructor.
 * Rather than re-export libsrtp's static srtp_kdf_init/generate, we
 * exercise the same primitive (AES-128/256 ICM) through libsrtp's
 * public cipher API and confirm that, given the same KDF IV, the
 * cipher produces the same keystream we compute in Sage.
 *
 * Output format: one JSON object per test vector to stdout. The Sage
 * side then loads this file and compares.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <srtp2/srtp.h>
#include <srtp2/cipher.h>
#include <srtp2/crypto_types.h>

extern srtp_cipher_type_t srtp_aes_icm_128;
extern srtp_cipher_type_t srtp_aes_icm_256;
extern srtp_cipher_type_t srtp_aes_gcm_128;
extern srtp_cipher_type_t srtp_aes_gcm_256;

/* SRTP-KDF IV as libsrtp 2.7.0 constructs it (srtp/srtp.c, srtp_kdf_generate):
 *   - the cipher's set_iv() callback already XORs the supplied IV with the
 *     14-byte master_salt that was packed behind the key in srtp_cipher_init.
 *   - so what srtp_kdf_generate hands to set_iv() is an all-zero 16-byte
 *     buffer with byte 7 set to `label`.
 * That matches RFC 3711 §4.3.3 once you fold in the master_salt XOR that
 * happens inside set_iv().
 */
static void make_kdf_iv(uint8_t iv16[16], const uint8_t master_salt14[14],
                        uint8_t label)
{
    (void)master_salt14;  /* applied internally by set_iv() */
    memset(iv16, 0, 16);
    iv16[7] = label;
}

static void hexdump(const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
}

/* `master_salt_len` is the number of meaningful salt bytes the caller
 * has. The libsrtp cipher always reads exactly SRTP_SALT_LEN=14 bytes,
 * so we zero-pad to 14 internally — mimicking libsrtp's own behaviour
 * in srtp_stream_init_keys() for the AEAD profile where the on-wire
 * master_salt is 12 bytes (RFC 7714) but the legacy CTR KDF still uses
 * 14-byte salts (see srtp/srtp.c:1037-1041 comment). */
static int do_one(const char *tag, const srtp_cipher_type_t *ct,
                  int key_len_with_salt,
                  const uint8_t *master_key, size_t mk_len,
                  const uint8_t *master_salt, size_t master_salt_len,
                  uint8_t label, size_t out_len)
{
    srtp_cipher_t *c = NULL;
    srtp_err_status_t st;

    if (master_salt_len != 12 && master_salt_len != 14) {
        fprintf(stderr, "[%s] unsupported master_salt_len=%zu\n",
                tag, master_salt_len);
        return 1;
    }

    /* In libsrtp's API the "key" passed to srtp_cipher_init is
     * master_key || master_salt, but for KDF use we instead set the
     * IV ourselves and use only the master_key as the AES key. To do
     * that cleanly, we allocate a cipher with key_len = mk_len and
     * salt_len = 14 (the WSALT length), but only the first mk_len
     * bytes of the buffer we pass to srtp_cipher_init are the AES
     * key; the rest is the "salt" that libsrtp will use for IV
     * construction. We OVERRIDE that with our own KDF-style IV via
     * srtp_cipher_set_iv() before each call. */

    st = srtp_cipher_type_alloc(ct, &c, (int)mk_len + 14, 16);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] srtp_cipher_type_alloc failed: %d\n", tag, st);
        return 1;
    }

    /* Pack master_key || (master_salt zero-padded to 14) for
     * srtp_cipher_init. Zero-padding the 12-byte AEAD salt to 14 here
     * exactly matches what srtp_stream_init_keys does upstream. */
    uint8_t init_buf[64];
    memset(init_buf, 0, sizeof(init_buf));
    memcpy(init_buf, master_key, mk_len);
    memcpy(init_buf + mk_len, master_salt, master_salt_len);
    st = srtp_cipher_init(c, init_buf);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] srtp_cipher_init failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }

    /* Build the SRTP-KDF IV and feed it to the cipher. */
    uint8_t iv[16];
    make_kdf_iv(iv, master_salt, label);
    st = srtp_cipher_set_iv(c, iv, srtp_direction_encrypt);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] srtp_cipher_set_iv failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }

    /* Generate keystream by encrypting zeros. */
    uint8_t out[256];
    if (out_len > sizeof(out)) {
        fprintf(stderr, "[%s] out_len too big\n", tag);
        srtp_cipher_dealloc(c);
        return 1;
    }
    memset(out, 0, out_len);
    uint32_t nbytes = (uint32_t)out_len;
    st = srtp_cipher_encrypt(c, out, &nbytes);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] srtp_cipher_encrypt failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }

    printf("  {\"tag\":\"%s\",\"master_key\":\"", tag);
    hexdump(master_key, mk_len);
    printf("\",\"master_salt\":\"");
    hexdump(master_salt, master_salt_len);
    printf("\",\"label\":\"0x%02x\",\"out_len\":%zu,\"out\":\"", label, out_len);
    hexdump(out, out_len);
    printf("\"}");

    srtp_cipher_dealloc(c);
    return 0;
}

/* GCM test: encrypt `plaintext` with libsrtp's AES-GCM using the given
 * key + nonce + AAD and dump the resulting ciphertext and 16-byte tag.
 *
 * libsrtp's GCM cipher_type takes `key_len = key + salt(12)` to its
 * type_alloc, but for KDF-style use we just want to drive AES-GCM
 * directly. Empirically, set_iv() takes the full 12-byte nonce, and
 * the salt portion of the init buffer is XORed in. To get a clean
 * GCM with our own nonce, we pass salt = 12 zero bytes and use
 * `nonce` as the IV.
 *
 * tlen for type_alloc is the tag length: 16 bytes for full GCM.
 */
static int do_gcm(const char *tag, const srtp_cipher_type_t *ct,
                  const uint8_t *master_key, size_t mk_len,
                  const uint8_t nonce12[12],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *plaintext, size_t pt_len)
{
    srtp_cipher_t *c = NULL;
    srtp_err_status_t st;

    st = srtp_cipher_type_alloc(ct, &c, (int)mk_len + 12, 16);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] type_alloc failed: %d\n", tag, st);
        return 1;
    }

    uint8_t init_buf[64];
    memcpy(init_buf, master_key, mk_len);
    memset(init_buf + mk_len, 0, 12);  /* zero salt → set_iv uses our nonce as-is */
    st = srtp_cipher_init(c, init_buf);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] cipher_init failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }

    uint8_t iv[16];
    memcpy(iv, nonce12, 12);
    iv[12] = iv[13] = iv[14] = iv[15] = 0;  /* set_iv reads 12 bytes for GCM */
    st = srtp_cipher_set_iv(c, iv, srtp_direction_encrypt);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] set_iv failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }

    if (aad_len > 0) {
        st = srtp_cipher_set_aad(c, aad, (uint32_t)aad_len);
        if (st != srtp_err_status_ok) {
            fprintf(stderr, "[%s] set_aad failed: %d\n", tag, st);
            srtp_cipher_dealloc(c);
            return 1;
        }
    }

    /* Encrypt in place; libsrtp's GCM cipher does NOT append the tag
     * automatically — we have to fetch it separately with get_tag(). */
    uint8_t buf[1024];
    if (pt_len > sizeof(buf)) {
        fprintf(stderr, "[%s] plaintext too big\n", tag);
        srtp_cipher_dealloc(c);
        return 1;
    }
    memcpy(buf, plaintext, pt_len);
    uint32_t outlen = (uint32_t)pt_len;
    st = srtp_cipher_encrypt(c, buf, &outlen);
    if (st != srtp_err_status_ok) {
        fprintf(stderr, "[%s] encrypt failed: %d\n", tag, st);
        srtp_cipher_dealloc(c);
        return 1;
    }
    uint8_t *ciphertext = buf;

    /* Fetch the 16-byte authentication tag separately. */
    uint8_t tag16[16];
    uint32_t taglen = sizeof(tag16);
    st = srtp_cipher_get_tag(c, tag16, &taglen);
    if (st != srtp_err_status_ok || taglen != 16) {
        fprintf(stderr, "[%s] get_tag failed: %d taglen=%u\n",
                tag, st, taglen);
        srtp_cipher_dealloc(c);
        return 1;
    }

    printf("  {\"tag\":\"%s\",\"key\":\"", tag);
    hexdump(master_key, mk_len);
    printf("\",\"nonce\":\"");
    hexdump(nonce12, 12);
    printf("\",\"aad\":\"");
    hexdump(aad, aad_len);
    printf("\",\"plaintext\":\"");
    hexdump(plaintext, pt_len);
    printf("\",\"ciphertext\":\"");
    hexdump(ciphertext, pt_len);
    printf("\",\"auth_tag\":\"");
    hexdump(tag16, 16);
    printf("\"}");

    srtp_cipher_dealloc(c);
    return 0;
}


int main(void)
{
    if (srtp_init() != srtp_err_status_ok) {
        fprintf(stderr, "srtp_init failed\n");
        return 1;
    }

    /* Two deterministic test vectors:
     *   #1 — AES-128: master_key 0x11..11, salt 0x22..22
     *   #2 — AES-256: master_key 0x33..33, salt 0x44..44
     * For each, derive label=0x00 (K_enc) and label=0x02 (S_session)
     * lengths that match Linphone's inner-encryption configuration
     * (paper App. C eq. 16-17: 32 bytes for AES-256 K_enc, 12 bytes
     * for S_session). For AES-128 we test 16 + 14 just as a sanity
     * pair.
     */
    uint8_t mk128[16];
    uint8_t mk256[32];
    uint8_t salt[14];
    uint8_t salt12[12];     /* AEAD-style 12-byte master_salt */
    memset(mk128, 0x11, sizeof(mk128));
    memset(mk256, 0x33, sizeof(mk256));
    memset(salt,  0x22, sizeof(salt));
    memset(salt12, 0x55, sizeof(salt12));

    printf("[\n");

    /* Legacy 14-byte salt path (AES-CM convention). */
    do_one("aes128_label00_L16", &srtp_aes_icm_128, 16+14,
           mk128, 16, salt, 14, 0x00, 16);
    printf(",\n");
    do_one("aes128_label02_L14", &srtp_aes_icm_128, 16+14,
           mk128, 16, salt, 14, 0x02, 14);
    printf(",\n");

    /* For the AES-256 case, swap the salt so the two vectors are
     * independent. */
    memset(salt, 0x44, sizeof(salt));
    do_one("aes256_label00_L32", &srtp_aes_icm_256, 32+14,
           mk256, 32, salt, 14, 0x00, 32);
    printf(",\n");
    do_one("aes256_label02_L12", &srtp_aes_icm_256, 32+14,
           mk256, 32, salt, 14, 0x02, 12);
    printf(",\n");

    /* AEAD-256-GCM KDF path: 12-byte master_salt zero-padded to 14
     * inside the cipher init. This is what Linphone actually does at
     * runtime when it hands the inner master_key||master_salt to libsrtp
     * via ms_media_stream_sessions_set_srtp_inner_send_key. */
    do_one("aead256_label00_L32_salt12", &srtp_aes_icm_256, 32+14,
           mk256, 32, salt12, 12, 0x00, 32);
    printf(",\n");
    do_one("aead256_label02_L12_salt12", &srtp_aes_icm_256, 32+14,
           mk256, 32, salt12, 12, 0x02, 12);
    printf(",\n");

    /* AES-GCM vectors. paper App. C eq. (21): AES-GCM.Enc(K_enc, P=data_voip,
     * n=nonce, aad=Header_RTP). We exercise AES-256-GCM (the inner cipher
     * Linphone uses) plus AES-128-GCM for completeness. */
    uint8_t gcm_key128[16];
    uint8_t gcm_key256[32];
    uint8_t gcm_nonce[12];
    uint8_t gcm_aad[16];
    uint8_t gcm_plaintext[64];
    memset(gcm_key128, 0x55, sizeof(gcm_key128));
    memset(gcm_key256, 0x66, sizeof(gcm_key256));
    memset(gcm_nonce,  0x77, sizeof(gcm_nonce));
    memset(gcm_aad,    0x88, sizeof(gcm_aad));
    for (size_t i = 0; i < sizeof(gcm_plaintext); i++) gcm_plaintext[i] = (uint8_t)i;

    do_gcm("gcm128_no_aad",       &srtp_aes_gcm_128,
           gcm_key128, 16, gcm_nonce, NULL, 0,
           gcm_plaintext, 32);
    printf(",\n");
    do_gcm("gcm128_with_aad",     &srtp_aes_gcm_128,
           gcm_key128, 16, gcm_nonce, gcm_aad, 12,
           gcm_plaintext, 48);
    printf(",\n");
    do_gcm("gcm256_no_aad",       &srtp_aes_gcm_256,
           gcm_key256, 32, gcm_nonce, NULL, 0,
           gcm_plaintext, 32);
    printf(",\n");
    do_gcm("gcm256_with_aad",     &srtp_aes_gcm_256,
           gcm_key256, 32, gcm_nonce, gcm_aad, 12,
           gcm_plaintext, 48);

    printf("\n]\n");
    srtp_shutdown();
    return 0;
}
