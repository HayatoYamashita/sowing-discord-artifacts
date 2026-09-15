import argparse
import sys
from binascii import unhexlify
from Crypto.Cipher import AES

CORRECTION_BLOCK_SIZE = 16

def decode_uleb128(data, offset):
    """Decode an unsigned LEB128 integer from a byte array."""
    result = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 too long")
    return result, offset

def parse_frame_payload(payload):
    """Parse protocol footer from the payload to extract ciphertext, tag, nonce, and ranges."""
    if len(payload) < 8 + 1 + 1 + 2:
        raise ValueError("frame too short")
    if payload[-2:] != b'\xFA\xFA':
        raise ValueError("magic 0xFAFA not found")

    supp_size = payload[-3]
    footer_end = len(payload) - 3
    footer_start = footer_end - supp_size
    if footer_start < 0:
        raise ValueError("invalid supp_size")

    footer = payload[footer_start:footer_end]
    ciphertext = payload[:footer_start]

    tag8 = footer[:8]
    nonce_int, next_off = decode_uleb128(footer, 8)

    range_count, next_off = decode_uleb128(footer, next_off)
    ranges = []
    for _ in range(range_count):
        r_off, next_off = decode_uleb128(footer, next_off)
        r_sz, next_off = decode_uleb128(footer, next_off)
        ranges.append((r_off, r_sz))

    return ciphertext, tag8, nonce_int, ranges

def build_nonce_bytes(nonce_int):
    """Construct the 12-byte AES-GCM IV using the decoded nonce integer."""
    return b'\x00' * 8 + (nonce_int & 0xFFFFFFFF).to_bytes(4, 'big')

def decrypt_with_key(ciphertext, tag8, nonce_int, key, aad=b''):
    """Decrypt payload using AES-GCM and verify the 8-byte MAC."""
    nonce = build_nonce_bytes(nonce_int)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=8)
    
    if aad:
        cipher.update(aad)
        
    try:
        pt = cipher.decrypt_and_verify(ciphertext, tag8)
        return pt, True
    except ValueError:
        cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=8)
        if aad:
            cipher2.update(aad)
        pt = cipher2.decrypt(ciphertext)
        return pt, False

def extract_clean_h265(plaintext):
    """Extract valid H.265 NAL units by isolating data between the first start code and the trailing noise."""
    sc = plaintext.find(b'\x00\x00\x01')
    if sc < 0:
        return b''
    if sc > 0 and plaintext[sc - 1] == 0:
        sc -= 1

    end = len(plaintext) - CORRECTION_BLOCK_SIZE
    if end <= sc:
        return b''
    return plaintext[sc:end]

def iter_frames(blob):
    """Yield (index, payload) tuples by reading 4-byte length prefixes."""
    off = 0
    frame_index = 0
    while off + 4 <= len(blob):
        n = int.from_bytes(blob[off:off + 4], 'big')
        off += 4
        if off + n > len(blob):
            raise ValueError(f"truncated frame at index {frame_index}")
        yield frame_index, blob[off:off + n]
        off += n
        frame_index += 1

def main():
    """Main driver to parse the input file, decrypt frames with both keys, and extract streams."""
    ap = argparse.ArgumentParser(description="Decrypt ENV-less polyglot payload.")
    ap.add_argument('-i', '--input', default='polyglot_h265.bin', help='Input polyglot binary')
    ap.add_argument('-k1', required=True, help='Key 1 (hex)')
    ap.add_argument('-k2', required=True, help='Key 2 (hex)')
    ap.add_argument('-oA', '--output_a', default='decrypted_key1.h265', help='Output H.265 for key1')
    ap.add_argument('-oB', '--output_b', default='decrypted_key2.h265', help='Output H.265 for key2')
    ap.add_argument('--dump-raw', action='store_true', help='Dump raw plaintext')
    args = ap.parse_args()

    key1 = unhexlify(args.k1)
    key2 = unhexlify(args.k2)

    with open(args.input, 'rb') as f:
        blob = f.read()

    frames = list(iter_frames(blob))
    print(f"[*] Parsed {len(frames)} frames from {args.input} ({len(blob):,} B total)")

    output_stream_a = bytearray()
    output_stream_b = bytearray()
    raw_stream_a = bytearray() if args.dump_raw else None
    raw_stream_b = bytearray() if args.dump_raw else None

    mac_success_count_1 = 0
    mac_success_count_2 = 0

    for frame_index, payload in frames:
        try:
            ct, tag8, nonce_int, ranges = parse_frame_payload(payload)
        except ValueError as e:
            print(f"[-] Frame {frame_index:04d}: parse failed: {e}")
            continue

        if ranges:
            print(f"[!] Frame {frame_index:04d}: non-empty ranges ({len(ranges)}); AAD cannot be reconstructed, MAC will fail.")

        aad = b''
        pt1, mac1_ok = decrypt_with_key(ct, tag8, nonce_int, key1, aad)
        pt2, mac2_ok = decrypt_with_key(ct, tag8, nonce_int, key2, aad)

        mac_success_count_1 += int(mac1_ok)
        mac_success_count_2 += int(mac2_ok)

        clean1 = extract_clean_h265(pt1)
        clean2 = extract_clean_h265(pt2)

        output_stream_a.extend(clean1)
        output_stream_b.extend(clean2)
        if args.dump_raw:
            raw_stream_a.extend(pt1)
            raw_stream_b.extend(pt2)

        print(f" [+] Frame {frame_index:04d} | nonce={nonce_int} | ct={len(ct):,}B | "
              f"k1:{'OK' if mac1_ok else 'FAIL'}({len(clean1):,}B) | "
              f"k2:{'OK' if mac2_ok else 'FAIL'}({len(clean2):,}B)")

    with open(args.output_a, 'wb') as f:
        f.write(output_stream_a)
    with open(args.output_b, 'wb') as f:
        f.write(output_stream_b)

    if args.dump_raw:
        with open(args.output_a + '.raw', 'wb') as f:
            f.write(raw_stream_a)
        with open(args.output_b + '.raw', 'wb') as f:
            f.write(raw_stream_b)

    print()
    print(f"[*] Key1 MAC success: {mac_success_count_1}/{len(frames)}  -> {args.output_a} ({len(output_stream_a):,} B)")
    print(f"[*] Key2 MAC success: {mac_success_count_2}/{len(frames)}  -> {args.output_b} ({len(output_stream_b):,} B)")

if __name__ == '__main__':
    main()