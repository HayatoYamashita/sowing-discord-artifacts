"""Build a minimal RTP fixed header (12 B) + optional CSRC list to serve
as AAD for Linphone's inner AES-GCM encryption (paper App. C eq. 20-21,
RFC 8723 §2.1 with extension excluded — Linphone's ms_srtp.cpp clears
`extbit` before handing the synthetic packet to libsrtp).

The 12-byte RTP fixed header (RFC 3550 §5.1) is:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |V=2|P|X|  CC   |M|     PT      |       sequence number         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           timestamp                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           synchronization source (SSRC) identifier            |
  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
  |            contributing source (CSRC) identifiers             |
  |                             ....                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The total length is 12 + 4 * CC bytes, which is exactly the AAD that
Linphone's inner srtp_protect_aead binds (libsrtp's enc_start - hdr =
12 + 4*CC since the synthetic packet has extbit=0).
"""

def build_rtp_header(*, version: int = 2,
                     padding: bool = False,
                     extension: bool = False,
                     csrcs: list = None,
                     marker: bool = False,
                     payload_type: int = 96,
                     seq: int = 0,
                     timestamp: int = 0,
                     ssrc: int = 0) -> bytes:
    """Return the wire-format RTP fixed header (12 B) + CSRC list.

    `csrcs` is a list of up to 15 contributing-source identifiers
    (uint32). If None or empty, CC = 0 and no CSRC bytes are appended.

    `extension` is left as a regular flag in the byte (so the AAD bytes
    match what Linphone's synthetic packet looks like — with extbit
    cleared by ms_srtp.cpp before inner encryption, this should be
    False for inner-encryption AAD computation).
    """
    csrcs = csrcs or []
    if not (0 <= len(csrcs) <= 15):
        raise ValueError("RTP allows at most 15 CSRC identifiers")
    if not (0 <= payload_type <= 127):
        raise ValueError("payload_type must fit in 7 bits")
    if not (0 <= seq <= 0xFFFF):
        raise ValueError("seq must fit in 16 bits")

    cc = len(csrcs)
    byte0 = ((version & 0x3) << 6) | ((1 if padding else 0) << 5) \
            | ((1 if extension else 0) << 4) | (cc & 0x0F)
    byte1 = ((1 if marker else 0) << 7) | (payload_type & 0x7F)

    out = bytearray()
    out.append(byte0)
    out.append(byte1)
    out += seq.to_bytes(2, "big")
    out += timestamp.to_bytes(4, "big")
    out += ssrc.to_bytes(4, "big")
    for csrc in csrcs:
        out += int(csrc).to_bytes(4, "big")
    assert len(out) == 12 + 4 * cc
    return bytes(out)


def selftest():
    # CC=0 minimal header
    h0 = build_rtp_header(payload_type=96, seq=42, timestamp=0xdeadbeef,
                          ssrc=0xcafebabe)
    assert len(h0) == 12
    # version=2 padding=0 extension=0 cc=0 → byte0 = 0x80
    # marker=0 pt=96 → byte1 = 0x60
    expected_head = b"\x80\x60" + (42).to_bytes(2, "big") + \
                    (0xdeadbeef).to_bytes(4, "big") + \
                    (0xcafebabe).to_bytes(4, "big")
    assert h0 == expected_head
    print(f"[+] CC=0 header: {len(h0)} B = {h0.hex()}")

    # CC=2 header
    h2 = build_rtp_header(payload_type=96, seq=42, timestamp=0xdeadbeef,
                          ssrc=0xcafebabe,
                          csrcs=[0x11111111, 0x22222222])
    assert len(h2) == 12 + 8 == 20
    print(f"[+] CC=2 header: {len(h2)} B = {h2.hex()}")
    # byte0 cc field = 2
    assert (h2[0] & 0x0F) == 2

    # CC=15 (max)
    h15 = build_rtp_header(payload_type=96, seq=42, timestamp=0xdeadbeef,
                           ssrc=0xcafebabe,
                           csrcs=list(range(0x10000000, 0x10000000 + 15)))
    assert len(h15) == 12 + 60 == 72
    print(f"[+] CC=15 header: {len(h15)} B = {h15.hex()}")
    print("[*] OK")


if __name__ == "__main__":
    selftest()
