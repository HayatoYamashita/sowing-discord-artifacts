/* test_attack_crypto — bit-for-bit equivalence check between the C
 * implementation (attack_crypto.c) and the sage implementation
 * under attack/crypto/ (the *.sage files), exercised over deterministic vectors
 * dumped by dump_ambig_vectors.sage. Reads ambig_vectors.json on stdin
 * and prints PASS/FAIL per vector. Exits non-zero on any mismatch.
 *
 * For each vector we additionally check the SRTP-KDF intermediates
 * (K_enc_old/new, nonce_old/new) so a diff localises the failure to
 * either the KDF, the AES-CTR, or the GHASH solver. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attack_crypto.h"

/* ---- tiny JSON-ish parser for our flat, key/value-only payload ---- */

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        int a = hex_nibble(hex[0]), b = hex_nibble(hex[1]);
        if (a < 0 || b < 0) break;
        if (n >= out_cap) return SIZE_MAX;
        out[n++] = (uint8_t)((a << 4) | b);
        hex += 2;
    }
    return n;
}

typedef struct {
    char *name;
    uint8_t master_key_old[32], master_key_new[32], master_salt[12];
    uint32_t ssrc, roc;
    uint16_t seq;
    uint8_t aad[128]; size_t aad_len;
    uint8_t plaintext[512]; size_t plaintext_len;
    size_t adjustment_offset;
    uint8_t expected_ct[512]; size_t expected_ct_len;
    uint8_t expected_tag[16];
    uint8_t k_enc_old_ref[32], k_enc_new_ref[32];
    uint8_t nonce_old_ref[12], nonce_new_ref[12];
} vec_t;

/* Find the first quoted-string value of a named JSON key inside `obj`.
 * Returns NULL if not found. The pointer points into `obj` (caller must
 * not free). Length is returned via *out_len. */
static const char *find_str(const char *obj, const char *key,
                            size_t *out_len) {
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return NULL;
    const char *p = strstr(obj, needle);
    if (!p) return NULL;
    p += n;
    while (*p == ' ') p++;
    if (*p != '"') return NULL;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return NULL;
    *out_len = (size_t)(end - p);
    return p;
}

static int find_int(const char *obj, const char *key, long long *out) {
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(obj, needle);
    if (!p) return -1;
    p += n;
    while (*p == ' ') p++;
    /* Accept either a bare integer or a hex string. */
    char *end;
    long long v = strtoll(p, &end, 0);
    if (end == p) return -1;
    *out = v;
    return 0;
}

static int decode_field(const char *obj, const char *key, uint8_t *out,
                        size_t cap, size_t *out_len, size_t expected_len) {
    size_t hlen = 0;
    const char *hex = find_str(obj, key, &hlen);
    if (!hex) {
        if (expected_len == 0) { *out_len = 0; return 0; }
        fprintf(stderr, "[-] missing field '%s'\n", key);
        return -1;
    }
    char buf[2048];
    if (hlen >= sizeof(buf)) {
        fprintf(stderr, "[-] field '%s' too long (%zu)\n", key, hlen);
        return -1;
    }
    memcpy(buf, hex, hlen);
    buf[hlen] = 0;
    size_t got = hex_decode(buf, out, cap);
    if (got == SIZE_MAX) {
        fprintf(stderr, "[-] field '%s' overflows buffer (%zu > cap %zu)\n",
                key, hlen / 2, cap);
        return -1;
    }
    if (expected_len > 0 && got != expected_len) {
        fprintf(stderr, "[-] field '%s' wrong length: got %zu, expected %zu\n",
                key, got, expected_len);
        return -1;
    }
    *out_len = got;
    return 0;
}

static int parse_vec(const char *obj, vec_t *v) {
    memset(v, 0, sizeof(*v));

    size_t name_len = 0;
    const char *name = find_str(obj, "name", &name_len);
    if (!name) { fprintf(stderr, "[-] no name\n"); return -1; }
    v->name = (char *)malloc(name_len + 1);
    memcpy(v->name, name, name_len);
    v->name[name_len] = 0;

    size_t dummy;
    if (decode_field(obj, "master_key_old", v->master_key_old, 32, &dummy, 32))
        return -1;
    if (decode_field(obj, "master_key_new", v->master_key_new, 32, &dummy, 32))
        return -1;
    if (decode_field(obj, "master_salt", v->master_salt, 12, &dummy, 12))
        return -1;
    if (decode_field(obj, "aad", v->aad, sizeof(v->aad), &v->aad_len, 0))
        return -1;
    if (decode_field(obj, "plaintext", v->plaintext, sizeof(v->plaintext),
                     &v->plaintext_len, 0))
        return -1;
    v->expected_ct_len = v->plaintext_len;
    if (decode_field(obj, "expected_ciphertext", v->expected_ct,
                     sizeof(v->expected_ct), &v->expected_ct_len,
                     v->plaintext_len))
        return -1;
    if (decode_field(obj, "expected_tag", v->expected_tag, 16, &dummy, 16))
        return -1;
    if (decode_field(obj, "K_enc_old", v->k_enc_old_ref, 32, &dummy, 32))
        return -1;
    if (decode_field(obj, "K_enc_new", v->k_enc_new_ref, 32, &dummy, 32))
        return -1;
    if (decode_field(obj, "nonce_old", v->nonce_old_ref, 12, &dummy, 12))
        return -1;
    if (decode_field(obj, "nonce_new", v->nonce_new_ref, 12, &dummy, 12))
        return -1;

    long long iv;
    if (find_int(obj, "ssrc", &iv)) return -1;
    v->ssrc = (uint32_t)iv;
    if (find_int(obj, "roc", &iv)) return -1;
    v->roc = (uint32_t)iv;
    if (find_int(obj, "seq", &iv)) return -1;
    v->seq = (uint16_t)iv;
    if (find_int(obj, "adjustment_offset", &iv)) return -1;
    v->adjustment_offset = (size_t)iv;
    return 0;
}

static char *slurp_stdin(size_t *out_len) {
    size_t cap = 8192, n = 0;
    char *buf = (char *)malloc(cap);
    int c;
    while ((c = getchar()) != EOF) {
        if (n + 1 >= cap) {
            cap *= 2;
            buf = (char *)realloc(buf, cap);
        }
        buf[n++] = (char)c;
    }
    buf[n] = 0;
    *out_len = n;
    return buf;
}

static void hexdump_eq(const char *label, const uint8_t *a, const uint8_t *b,
                       size_t n) {
    fprintf(stderr, "   %s   ours: ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", a[i]);
    fprintf(stderr, "\n   %s    ref: ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

static int check_vec(const vec_t *v) {
    ambig_session_keys_t keys;
    /* Standalone test vectors use a single shared salt for both K_old
     * and K_new (the rotation-with-changed-salt case is exercised only
     * at runtime by the live hook). */
    if (ambig_derive_session_keys(v->master_key_old, v->master_salt,
                                  v->master_key_new, v->master_salt,
                                  &keys) != 0) {
        fprintf(stderr, "[FAIL] %s: ambig_derive_session_keys failed\n",
                v->name);
        return 1;
    }

    int kdf_fail = 0;
    if (memcmp(keys.k_enc_old, v->k_enc_old_ref, 32) != 0) {
        fprintf(stderr, "[FAIL] %s: K_enc_old mismatch\n", v->name);
        hexdump_eq("K_enc_old", keys.k_enc_old, v->k_enc_old_ref, 32);
        kdf_fail = 1;
    }
    if (memcmp(keys.k_enc_new, v->k_enc_new_ref, 32) != 0) {
        fprintf(stderr, "[FAIL] %s: K_enc_new mismatch\n", v->name);
        hexdump_eq("K_enc_new", keys.k_enc_new, v->k_enc_new_ref, 32);
        kdf_fail = 1;
    }
    if (kdf_fail) return 1;

    uint8_t ct[512] = {0};
    uint8_t tag[16] = {0};
    if (ambig_build_packet(&keys, v->ssrc, v->roc, v->seq, v->aad, v->aad_len,
                           v->plaintext, v->plaintext_len,
                           v->adjustment_offset, ct, tag) != 0) {
        fprintf(stderr, "[FAIL] %s: ambig_build_packet failed\n", v->name);
        return 1;
    }

    if (memcmp(ct, v->expected_ct, v->plaintext_len) != 0) {
        fprintf(stderr, "[FAIL] %s: ciphertext mismatch (%zu B)\n", v->name,
                v->plaintext_len);
        hexdump_eq("CT", ct, v->expected_ct, v->plaintext_len);
        return 1;
    }
    if (memcmp(tag, v->expected_tag, 16) != 0) {
        fprintf(stderr, "[FAIL] %s: tag mismatch\n", v->name);
        hexdump_eq("TAG", tag, v->expected_tag, 16);
        return 1;
    }
    printf("[PASS] %-26s  plaintext=%3zu B  AAD=%2zu B  adj=%3zu\n",
           v->name, v->plaintext_len, v->aad_len, v->adjustment_offset);
    return 0;
}

int main(void) {
    size_t json_len = 0;
    char *json = slurp_stdin(&json_len);

    /* Find each object literal (between '{' and the matching '}'). The
     * vectors are flat (no nested braces), so depth-1 brace matching is
     * sufficient. */
    int total = 0, failed = 0;
    const char *p = json;
    while ((p = strchr(p, '{')) != NULL) {
        int depth = 0;
        const char *start = p;
        const char *q = p;
        while (*q) {
            if (*q == '{') depth++;
            else if (*q == '}') {
                depth--;
                if (depth == 0) { q++; break; }
            }
            q++;
        }
        if (depth != 0) break;
        size_t obj_len = (size_t)(q - start);
        char *obj = (char *)malloc(obj_len + 1);
        memcpy(obj, start, obj_len);
        obj[obj_len] = 0;

        vec_t v;
        if (parse_vec(obj, &v) == 0) {
            total++;
            if (check_vec(&v) != 0) failed++;
        }
        free(obj);
        free(v.name);
        p = q;
    }
    free(json);

    printf("\n%s: %d/%d vectors matched the reference bit-for-bit\n",
           failed == 0 ? "[+] OK" : "[-] FAIL", total - failed, total);
    return failed == 0 ? 0 : 1;
}
