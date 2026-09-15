/* Stand-in for libsrtp's srtp_create/srtp_protect. Lives in its OWN
 * dylib so that libfake_ms.dylib's calls into these functions go through
 * the dynamic linker, which is where DYLD_INTERPOSE actually rewrites
 * bindings. (Intra-library calls within the same dylib do not go through
 * dyld and cannot be interposed.) */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int srtp_create(void **session_out, const void *policy) {
    (void)policy;
    if (!session_out) return -1;
    *session_out = malloc(8);
    fprintf(stderr, "[fake-srtp] real srtp_create -> %p\n", *session_out);
    return 0;
}

int srtp_protect(void *ctx, void *rtp_hdr, int *len_ptr) {
    (void)rtp_hdr;
    fprintf(stderr, "[fake-srtp] real srtp_protect for session=%p len_in=%d\n",
            ctx, len_ptr ? *len_ptr : -1);
    if (len_ptr) *len_ptr += 16;
    return 0;
}

#include <stdint.h>
int srtp_get_stream_roc(void *session, uint32_t ssrc, uint32_t *roc) {
    (void)session; (void)ssrc;
    if (roc) *roc = 0x42;
    return 0;
}
