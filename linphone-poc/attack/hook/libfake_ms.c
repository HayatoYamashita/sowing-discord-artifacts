/* Stand-in for libmediastreamer2's ms_media_stream_sessions_set_srtp_inner_send_key.
 * Only purpose: exist as a dyld-resolvable shared symbol so that
 * DYLD_INSERT_LIBRARIES + __interpose can actually rewrite the binding
 * when smoke_test calls it. (Without this, smoke_test's own internal
 * definition would not go through the dynamic linker and the
 * interposer would never fire.) */

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

/* srtp_create / srtp_protect live in libfake_srtp.dylib — calling them
 * from THIS dylib produces a cross-library reference that goes through
 * the dynamic linker (and is therefore interposable). */
extern int srtp_create(void **session_out, const void *policy);
extern int srtp_protect(void *ctx, void *rtp_hdr, int *len_ptr);

/* Smoke-test plumbing: remember the most recent inner srtp_t so the
 * smoke test can drive a srtp_protect call against it without poking
 * at libsrtp internals. */
static void *g_last_inner_srtp = NULL;
void *fake_ms_last_inner_srtp(void) { return g_last_inner_srtp; }

int ms_media_stream_sessions_set_srtp_inner_send_key(void *sessions, int suite,
                                                     const uint8_t *key,
                                                     size_t key_length,
                                                     int source) {
    (void)sessions; (void)key; (void)key_length; (void)source;
    fprintf(stderr, "[fake-ms] real (stub) function entered — about to "
                    "call srtp_create from inside\n");
    void *new_session = NULL;
    srtp_create(&new_session, NULL);
    fprintf(stderr, "[fake-ms] srtp_create returned session=%p\n", new_session);
    /* Only AEAD-AES-256-GCM (= the suite the hook actually tags) is
     * relevant for the smoke test's INNER ATTACK exercise. */
    if (suite == 12) g_last_inner_srtp = new_session;
    return 0;
}

