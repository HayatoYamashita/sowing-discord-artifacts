"""SRTP-KDF used by Linphone's inner-encryption (paper App. C, eq. 14-19).

Derives, from a 32-byte `inner_master_key_sender` and a 12-byte master_salt
(the 14-byte CSPI prefix that survives `ekt->mSrtpMasterSalt` for the
AEAD_AES_256_GCM suite — vector sized to `SRTP_AEAD_SALT_LEN=12`), the
32-byte AES-256 session encryption key K_enc and the 12-byte session salt
S_session, which combine with SSRC/ROC/SEQ to give the per-packet GCM nonce.

The KDF (RFC 3711 §4.3.3, plus the AEAD extensions of RFC 7714) is:
  master_key, master_salt → SRTP-KDF(label, L) → L-byte derived key

  Internally: AES-CM with K=master_key, IV = encode_kdf_iv(label, master_salt)
  and we just take the first L bytes of the keystream.

For our Linphone inner-encryption setting, paper App. C specialises this
as:
  inner_key_material = inner_master_key_sender(32) || master_salt(12)
                       where master_salt = CSPI[0..12]
  K_enc      = SRTP-KDF(M=inner_key_material, label=0x00, L=32)
  S_session  = SRTP-KDF(M=inner_key_material, label=0x02, L=12)

Salt zero-padding (libsrtp 2.7.0 quirk): even though the AEAD profile
defines a 12-byte master_salt, libsrtp's KDF inside `srtp_stream_init_keys`
zero-pads to 14 bytes before running AES-CTR (`srtp/srtp.c:1037-1041`
comment "GCM mode uses a shorter master SALT (96 bits), but still relies
on the legacy CTR mode KDF, which uses a 112 bit master SALT").
We replicate that behaviour: the supplied 12-byte salt is zero-extended
to 14 bytes internally before the KDF IV is constructed.

For AES-GCM (the inner cipher), the per-packet nonce is then:
  in_nonce = 0x0000(2) || SSRC(4) || ROC(4) || SEQ(2)        (12 B)
  nonce    = in_nonce XOR S_session                          (12 B)
"""

from Crypto.Cipher import AES


def _zero_extend_salt_to_14(master_salt: bytes) -> bytes:
    """Zero-extend a 12-byte AEAD master_salt to the 14-byte legacy CTR-KDF
    salt that libsrtp's KDF actually consumes (srtp/srtp.c:1037-1041). A
    14-byte salt is passed through unchanged. Any other length is a bug."""
    if len(master_salt) == 14:
        return master_salt
    if len(master_salt) == 12:
        return master_salt + b"\x00\x00"
    raise ValueError(f"master_salt must be 12 or 14 bytes, got {len(master_salt)}")


def _srtp_kdf_iv(label: int, master_salt: bytes) -> bytes:
    """Build the 16-byte KDF IV from a 1-byte label and master_salt.

    Per RFC 3711 §4.3.3 the salt is conceptually 14 bytes; for AEAD profiles
    libsrtp internally zero-pads the 12-byte salt to 14. Either form is
    accepted here.

      x = master_salt(14) XOR (label || 0x000000000000)      (14 B)
      IV = x || 0x0000                                       (16 B)
    The packet-index byte is 0 here because we are doing the once-per-
    session key derivation, not per-packet keystream advance.
    """
    salt14 = _zero_extend_salt_to_14(master_salt)
    # Construct the 14-byte intermediate value: master_salt with `label`
    # XORed into byte index 7 (RFC 3711 §4.3.3 places the 1-byte label at
    # position 7 from the right in the 14-byte field).
    x = bytearray(salt14)
    x[7] = x[7] ^^ label   # Sage: ^^ is the bitwise XOR ('^' is exponentiation here)
    iv = bytes(x) + b"\x00\x00"
    return iv


def srtp_kdf(master_key: bytes, master_salt: bytes, label: int,
             out_len: int) -> bytes:
    """SRTP key derivation function. The key length picks AES-128/192/256.

    master_salt may be 12 bytes (AEAD profile, as Linphone provides) or
    14 bytes (legacy AES-CM profile). 12-byte input is zero-extended to
    14 bytes to match libsrtp's internal KDF behaviour."""
    if len(master_key) not in (16, 24, 32):
        raise ValueError(f"master_key length {len(master_key)} unsupported")
    iv16 = _srtp_kdf_iv(label, master_salt)
    # AES-CTR keystream truncated to out_len bytes.
    cipher = AES.new(master_key, AES.MODE_CTR, nonce=b"", initial_value=iv16)
    return cipher.encrypt(b"\x00" * out_len)


def derive_inner_keys(inner_master_key_sender: bytes, master_salt: bytes) -> dict:
    """Implement paper App. C eq. (14)-(17): from the per-sender inner
    master key and the conference's master_salt (= CSPI[:12] for the
    AEAD_AES_256_GCM suite Linphone uses), derive the AES-256 K_enc and
    the 12-byte session salt S_session.

    master_salt may be 12 bytes (Linphone's actual ekt->mSrtpMasterSalt
    for AEAD-256-GCM) or 14 bytes (legacy AES-CM convention). 12-byte
    input is zero-extended to 14 bytes internally to match libsrtp's KDF
    (srtp/srtp.c:1037-1041)."""
    if len(inner_master_key_sender) != 32:
        raise ValueError("inner_master_key_sender must be 32 bytes (AES-256)")
    salt14 = _zero_extend_salt_to_14(master_salt)
    inner_key_material = inner_master_key_sender + salt14            # eq. (15)
    k_enc     = srtp_kdf(inner_master_key_sender, salt14,
                         label=0x00, out_len=32)                     # eq. (16)
    s_session = srtp_kdf(inner_master_key_sender, salt14,
                         label=0x02, out_len=12)                     # eq. (17)
    return {"K_enc": k_enc, "S_session": s_session,
            "master_salt": master_salt,
            "salt_SrtpMaster": salt14,            # 14-byte zero-extended form
            "inner_key_material": inner_key_material}


def build_packet_nonce(ssrc: int, roc: int, seq: int,
                       s_session: bytes) -> bytes:
    """Implement paper App. C eq. (18)-(19): construct the per-packet
    AES-GCM nonce. SSRC and ROC are 4-byte big-endian, SEQ is 2-byte BE,
    and a 2-byte zero prefix pads everything to 12 bytes; then XOR with
    the session salt."""
    if len(s_session) != 12:
        raise ValueError("S_session must be 12 bytes")
    in_nonce = (b"\x00\x00"
                + ssrc.to_bytes(4, "big")
                + roc.to_bytes(4, "big")
                + seq.to_bytes(2, "big"))                # eq. (18)
    nonce = bytes(a ^^ b for a, b in zip(in_nonce, s_session))  # eq. (19)
    return nonce


def selftest():
    # Use a couple of fixed vectors and confirm that:
    #   - srtp_kdf is deterministic
    #   - derive_inner_keys returns the expected lengths
    #   - 12-byte and 14-byte salt forms agree when the trailing 2 bytes
    #     of the 14-byte form are zero (i.e., when the 14-byte form was
    #     itself derived by zero-extending a 12-byte salt)
    km = b"\x11" * 32
    salt12 = b"\x22" * 12
    salt14_zero_padded = salt12 + b"\x00\x00"

    kd = derive_inner_keys(km, salt12)
    assert len(kd["K_enc"]) == 32
    assert len(kd["S_session"]) == 12
    print(f"[+] K_enc      = {kd['K_enc'].hex()}")
    print(f"[+] S_session  = {kd['S_session'].hex()}")
    print(f"[+] salt_SrtpMaster (14 B, zero-padded) = {kd['salt_SrtpMaster'].hex()}")

    kd_alt = derive_inner_keys(km, salt14_zero_padded)
    assert kd["K_enc"] == kd_alt["K_enc"]
    assert kd["S_session"] == kd_alt["S_session"]
    print("[+] 12-byte vs 14-byte-zero-padded forms agree")

    n = build_packet_nonce(ssrc=0x12345678, roc=0xdeadbeef, seq=0x0042,
                           s_session=kd["S_session"])
    print(f"[+] nonce      = {n.hex()}  (per-packet)")

    # Sanity: same inputs → same outputs (KDF is deterministic).
    kd2 = derive_inner_keys(km, salt12)
    assert kd["K_enc"] == kd2["K_enc"]
    assert kd["S_session"] == kd2["S_session"]
    print("[+] determinism OK")


if __name__ == "__main__":
    selftest()
