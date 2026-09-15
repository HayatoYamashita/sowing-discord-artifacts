/* Minimal binary that pretends to call ms_media_stream_sessions_set_srtp_inner_send_key
 * twice with deterministic AEAD-AES-256-GCM-shaped buffers. When run
 * under DYLD_INSERT_LIBRARIES=libattack_hook.dylib, the hook should
 * capture both keys and log them, demonstrating that:
 *   (a) the interposer entry is wired correctly,
 *   (b) the sliding K_old/K_new window populates after two rotations,
 *   (c) the suite-dispatch and key/salt slicing are right.
 *
 * The "real" function in this test environment is just a stub returning 0
 * since we're not linking against libmediastreamer2 here. */

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Declared here, defined in libfake_ms.dylib — calls go through the
 * dyld symbol table, which is what the DYLD_INTERPOSE machinery
 * actually rewrites. */
extern int ms_media_stream_sessions_set_srtp_inner_send_key(
    void *sessions, int suite, const uint8_t *key, size_t key_length,
    int source);
extern int srtp_create(void **session_out, const void *policy);
extern int srtp_protect(void *ctx, void *rtp_hdr, int *len_ptr);
extern void *fake_ms_last_inner_srtp(void);

int main(void) {
    /* AEAD-AES-256-GCM enum value = 12; key+salt = 32+12 = 44 B. */
    uint8_t key_buf_1[44];
    uint8_t key_buf_2[44];
    memset(key_buf_1, 0x11, sizeof(key_buf_1));
    memset(key_buf_2, 0x22, sizeof(key_buf_2));
    /* Make the salts distinguishable from the keys. */
    memset(key_buf_1 + 32, 0xa1, 12);
    memset(key_buf_2 + 32, 0xa2, 12);

    fprintf(stderr, "[smoke] calling setter (initial K_new — no K_old yet)\n");
    ms_media_stream_sessions_set_srtp_inner_send_key(NULL, 12, key_buf_1, 44, 4);

    fprintf(stderr, "[smoke] calling setter (rotation — K_old should slide in)\n");
    ms_media_stream_sessions_set_srtp_inner_send_key(NULL, 12, key_buf_2, 44, 4);

    fprintf(stderr, "[smoke] calling setter with an unrecognized suite\n");
    ms_media_stream_sessions_set_srtp_inner_send_key(NULL, 7 /* SHA1_80 */,
                                                     key_buf_1, 30, 1);

    /* --- Step 2.5d additional checks ---
     * Create an srtp_t OUTSIDE the inner-setup path — must NOT be tagged
     * as inner. Then call srtp_protect with both an inner srtp_t (the
     * last one created via the inner setup) and this outer one, and
     * verify the hook classifies correctly. */
    fprintf(stderr, "\n[smoke] creating an srtp_t OUTSIDE inner-setup "
                    "(should NOT be tagged inner)\n");
    void *outer_session = NULL;
    srtp_create(&outer_session, NULL);

    uint8_t fake_rtp[256];
    memset(fake_rtp, 0x42, sizeof(fake_rtp));
    int rtp_len = 100;

    /* The inner srtp_t we want to verify is the one created during
     * the most recent inner setup. Since libfake_ms creates a new
     * srtp_t every call and we don't track it, just call srtp_protect
     * with the outer_session and confirm the hook says [outer]. */
    fprintf(stderr, "[smoke] srtp_protect on outer_session=%p (expect [outer] tag)\n",
            outer_session);
    srtp_protect(outer_session, fake_rtp, &rtp_len);

    /* Drive inner srtp_protect to exercise the ATTACK / observe / pass-through
     * branches end-to-end. Build a plausible-looking RTP packet (V=2,
     * CC=0, PT=96 dynamic, SSRC=cafebabe) with 256 B of "sender" payload. */
    void *inner = fake_ms_last_inner_srtp();
    if (inner) {
        uint8_t rtp[512];
        memset(rtp, 0x55, sizeof(rtp));
        rtp[0] = 0x80;                 /* V=2 P=0 X=0 CC=0 */
        rtp[1] = 0x60;                 /* M=0 PT=96 */
        rtp[2] = 0x12; rtp[3] = 0x34;  /* seq */
        rtp[4] = 0xde; rtp[5] = 0xad; rtp[6] = 0xbe; rtp[7] = 0xef;  /* ts */
        rtp[8] = 0xca; rtp[9] = 0xfe; rtp[10]= 0xba; rtp[11]= 0xbe;  /* ssrc */

        int len = 12 + 256;
        fprintf(stderr, "\n[smoke] srtp_protect on INNER session=%p "
                        "len=%d (ARM=%s)\n",
                inner, len, getenv("ATTACK_HOOK_ARM") ? "1" : "unset");
        srtp_protect(inner, rtp, &len);
        fprintf(stderr, "[smoke] returned len=%d\n", len);
    } else {
        fprintf(stderr, "[smoke] no inner srtp_t available\n");
    }

    return 0;
}
