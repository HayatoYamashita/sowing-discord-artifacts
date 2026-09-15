"""Dump a JSON file of deterministic test vectors for the C ambiguous-
ciphertext builder to validate against. The vectors cover:

  - CC=0/1/2/3 AAD layouts (12, 16, 20, 24 bytes after RTP header build)
  - plaintext sizes spanning 1, 2, 5, 13 ciphertext blocks
  - adjustment_offset placed at block index 0, 1, mid, last

Each vector lists the inputs (so the C side recomputes from scratch)
plus the expected outputs (ciphertext bytes + 16-byte tag) so the C
test harness can compare bit-for-bit.

To regenerate: sage attack/hook/dump_ambig_vectors.sage > attack/hook/ambig_vectors.json
"""

from binascii import hexlify, unhexlify
import json

load('attack/crypto/util.sage')
load('attack/crypto/gcm.sage')
load('attack/crypto/srtp_kdf.sage')
load('attack/crypto/test_packet_ambiguous.sage')
load('attack/crypto/rtp_header.sage')


def make_vec(name, *, master_key_old, master_key_new, master_salt,
             ssrc, roc, seq, aad, plaintext, adjustment_offset):
    """Run build_ambiguous_under_inner_keys and dump everything we need
    to reproduce in C: inputs (hex) + expected outputs (hex)."""
    r = build_ambiguous_under_inner_keys(
        plaintext, master_key_old, master_key_new, master_salt,
        ssrc, roc, seq,
        adjustment_block_offset=adjustment_offset, aad=aad,
    )
    return {
        "name": name,
        "master_key_old":   hexlify(master_key_old).decode(),
        "master_key_new":   hexlify(master_key_new).decode(),
        "master_salt":      hexlify(master_salt).decode(),
        "ssrc":             int(ssrc),
        "roc":              int(roc),
        "seq":              int(seq),
        "aad":              hexlify(aad).decode(),
        "plaintext":        hexlify(plaintext).decode(),
        "adjustment_offset": int(adjustment_offset),
        "expected_ciphertext": hexlify(r["ciphertext"]).decode(),
        "expected_tag":        hexlify(r["tag16"]).decode(),
        # Surface the derived session keys/nonces so the C test can
        # cross-check each intermediate step.
        "K_enc_old":     hexlify(r["K_enc_old"]).decode(),
        "K_enc_new":     hexlify(r["K_enc_new"]).decode(),
        "nonce_old":     hexlify(r["nonce_old"]).decode(),
        "nonce_new":     hexlify(r["nonce_new"]).decode(),
    }


def main():
    # Common inputs.
    K_OLD = unhexlify("000102030405060708090a0b0c0d0e0f"
                      "101112131415161718191a1b1c1d1e1f")
    K_NEW = unhexlify("ffeeddccbbaa99887766554433221100"
                      "fedcba9876543210ffeeddccbbaa9988")
    SALT  = unhexlify("aabbccddeeff001122334455")   # 12 B
    SSRC, ROC = 0xdeadbeef, 0x00000007

    vectors = []

    # Vec 1: tiny plaintext (1 block), CC=0 AAD, adj at offset 0.
    pt1 = b"\xab" * 16
    aad0 = build_rtp_header(payload_type=96, seq=0x0042, timestamp=0xdeadbeef,
                            ssrc=SSRC)
    vectors.append(make_vec("v1_1blk_cc0_adj0",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=ROC, seq=0x0042,
                            aad=aad0, plaintext=pt1, adjustment_offset=0))

    # Vec 2: 2 blocks (32 B), CC=1, adj at block 1 (offset 16).
    pt2 = b"\x11"*16 + b"\x22"*16
    aad1 = build_rtp_header(payload_type=96, seq=0x0100, timestamp=0xcafebabe,
                            ssrc=SSRC, csrcs=[0x10000001])
    vectors.append(make_vec("v2_2blk_cc1_adj1",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=ROC, seq=0x0100,
                            aad=aad1, plaintext=pt2, adjustment_offset=16))

    # Vec 3: 5 blocks (80 B), CC=2, adj at block 2 (mid).
    pt3 = b"".join((i.to_bytes(1, 'big') * 16) for i in range(0x30, 0x35))
    aad2 = build_rtp_header(payload_type=96, seq=0x1234, timestamp=0x12345678,
                            ssrc=SSRC, csrcs=[0x10000001, 0x10000002])
    vectors.append(make_vec("v3_5blk_cc2_adj2",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=ROC, seq=0x1234,
                            aad=aad2, plaintext=pt3, adjustment_offset=32))

    # Vec 4: 13 blocks (208 B), CC=3, adj at last block.
    pt4 = b"".join((i.to_bytes(1, 'big') * 16) for i in range(0x40, 0x4d))
    aad3 = build_rtp_header(payload_type=96, seq=0xfffe, timestamp=0x12345678,
                            ssrc=SSRC, csrcs=[0x10000001, 0x10000002, 0x10000003])
    vectors.append(make_vec("v4_13blk_cc3_adj_last",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=ROC, seq=0xfffe,
                            aad=aad3, plaintext=pt4, adjustment_offset=12*16))

    # Vec 5: no AAD (legacy / boundary). 3 blocks (48 B), adj at block 0.
    pt5 = b"\x55"*16 + b"\x66"*16 + b"\x77"*16
    vectors.append(make_vec("v5_3blk_no_aad_adj0",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=ROC, seq=0x00aa,
                            aad=b"", plaintext=pt5, adjustment_offset=0))

    # Vec 6: ROC ≠ 0 in nonce path (sanity).
    pt6 = b"\xCC"*32
    aad6 = build_rtp_header(payload_type=96, seq=0x0007, timestamp=0xdeadbeef,
                            ssrc=SSRC)
    vectors.append(make_vec("v6_2blk_high_roc",
                            master_key_old=K_OLD, master_key_new=K_NEW,
                            master_salt=SALT, ssrc=SSRC, roc=0x12345678, seq=0x0007,
                            aad=aad6, plaintext=pt6, adjustment_offset=16))

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
