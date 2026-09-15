import sys
import argparse
import time
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
import operator

load('gcm.sage')

def encode_uleb128(value):
    """Encode an integer to standard ULEB128 byte format."""
    out = bytearray()
    if value == 0:
        return b'\x00'
    while value > 0:
        b = value & 0x7F
        value >>= 7
        if value > 0:
            b |= 0x80
        out.append(b)
    return bytes(out)

def build_ranges_bytes(ranges):
    """Encode unencrypted ranges using ULEB128. Returns b'\\x00' if ranges is empty."""
    out = bytearray()
    out.extend(encode_uleb128(len(ranges)))
    for offset, size in ranges:
        out.extend(encode_uleb128(offset))
        out.extend(encode_uleb128(size))
    return bytes(out)

def build_footer(tag8, nonce_int, ranges_bytes):
    """Construct the target protocol footer."""
    footer = bytearray()
    footer.extend(tag8)

    nonce_leb128 = encode_uleb128(nonce_int)
    footer.extend(nonce_leb128)

    footer.extend(ranges_bytes)

    supp_size = len(tag8) + len(nonce_leb128) + len(ranges_bytes)
    footer.extend(supp_size.to_bytes(1, 'big'))

    footer.extend(b'\xFA\xFA')
    return bytes(footer)

def pad16(x):
    """Pad byte string to a multiple of 16 bytes."""
    if len(x) % 16 != 0:
        x += b"\x00" * (16 - len(x) % 16)
    return x

def extract_h265_nal_unit(data, offset):
    """Extract H.265 NAL unit chunk avoiding start code splits."""
    if offset >= len(data): return None, offset
    chunk_start = offset
    current_offset = offset
    has_vcl = False
    
    while current_offset < len(data):
        sc_pos = data.find(b'\x00\x00\x01', current_offset)
        if sc_pos == -1:
            current_offset = len(data)
            break
            
        start_pos = sc_pos - 1 if (sc_pos > 0 and data[sc_pos-1] == 0) else sc_pos
        if current_offset > chunk_start and has_vcl:
            current_offset = start_pos
            break
            
        nal_header_pos = sc_pos + 3
        if nal_header_pos < len(data):
            nal_type = (data[nal_header_pos] >> 1) & 0x3F
            if nal_type <= 31: has_vcl = True
            
        current_offset = nal_header_pos
        
    return data[chunk_start:current_offset], current_offset

def build_polyglot_payload(chunk_a, chunk_b, key1, key2, base_nonce_int):
    """
    Generate a polyglot payload.
    AAD and unencrypted ranges are empty. The entire concatenated chunk is encrypted.
    """
    interleaved_pt = chunk_a + chunk_b
    interleaved_pt = pad16(interleaved_pt)

    ad_blocks = []
    ad_len_bytes = 0

    for attempt in range(50):
        current_nonce_int = (base_nonce_int + attempt) & 0xFFFFFFFF
        current_nonce_bytes = b'\x00' * 8 + current_nonce_int.to_bytes(4, 'big')

        cipher1 = AES.new(key1, AES.MODE_GCM, nonce=current_nonce_bytes)
        cipher2 = AES.new(key2, AES.MODE_GCM, nonce=current_nonce_bytes)

        total_len = len(interleaved_pt) + 16
        KS1 = cipher1.encrypt(b"\x00" * total_len)
        KS2 = cipher2.encrypt(b"\x00" * total_len)

        C_base = bytearray(len(interleaved_pt))
        for i in range(len(chunk_a)):
            C_base[i] = operator.xor(interleaved_pt[i], KS1[i])
            
        offset = len(chunk_a)
        for i in range(offset, len(interleaved_pt)):
            C_base[i] = operator.xor(interleaved_pt[i], KS2[i])

        correction_placeholder = b'\x00' * 16
        C_full = bytes(C_base) + correction_placeholder

        num_ct_blocks = len(C_full) // 16
        ct_blocks = [C_full[i*16:(i+1)*16] for i in range(num_ct_blocks)]
        ct_correction_index = num_ct_blocks - 1

        _, _, final_ct_blocks, tag16 = gcm_1block(
            key1, key2, current_nonce_bytes, current_nonce_bytes,
            ct_correction_index,
            len(C_full), ct_blocks,
            ad_len_bytes, ad_blocks,
            ad_len_bytes, ad_blocks
        )

        final_ciphertext = b''.join(final_ct_blocks)

        p1_full = bytes(operator.xor(a, b) for a, b in zip(final_ciphertext, KS1))
        p2_full = bytes(operator.xor(a, b) for a, b in zip(final_ciphertext, KS2))

        p1_noise = p1_full[len(chunk_a):]
        p2_noise_front = p2_full[:len(chunk_a)]
        p2_noise_tail = p2_full[-16:]

        if (b'\x00\x00\x01' not in final_ciphertext and
            b'\x00\x00\x01' not in p1_noise and
            b'\x00\x00\x01' not in p2_noise_front and
            b'\x00\x00\x01' not in p2_noise_tail):

            if attempt > 0:
                print(f"     -> [Retry] SC collision detected. Nonce incremented by {attempt}.")

            tag8 = tag16[:8]
            return final_ciphertext, tag8, current_nonce_int

    raise ValueError("Failed to avoid SC within the retry limit (50).")

def main():
    parser = argparse.ArgumentParser(description="Protocol Polyglot Generator")
    parser.add_argument('-vA', '--video_a', required=True)
    parser.add_argument('-vB', '--video_b', required=True)
    parser.add_argument('-k1', required=True)
    parser.add_argument('-k2', required=True)
    parser.add_argument('-n', '--base_nonce', required=True)
    args = parser.parse_args()

    key1 = unhexlify(args.k1)
    key2 = unhexlify(args.k2)
    base_nonce_bytes = unhexlify(args.base_nonce)

    with open(args.video_a, "rb") as f: stream_a = f.read()
    with open(args.video_b, "rb") as f: stream_b = f.read()

    output_stream = bytearray()
    offset_a = 0
    offset_b = 0
    frame_id = 0

    print("[*] Generating Polyglot Stream...")

    start_time = time.perf_counter()

    while offset_a < len(stream_a) and offset_b < len(stream_b):
        chunk_a, offset_a = extract_h265_nal_unit(stream_a, offset_a)
        chunk_b, offset_b = extract_h265_nal_unit(stream_b, offset_b)
        if not chunk_a or not chunk_b: break

        unencrypted_ranges = []
        nonce_int = operator.xor(int.from_bytes(base_nonce_bytes, 'big'), frame_id)

        try:
            ciphertext, tag8, final_nonce_int = build_polyglot_payload(
                chunk_a, chunk_b, key1, key2, nonce_int
            )
        except ValueError as e:
            print(f"[-] Frame {frame_id} failed: {e}")
            break

        ranges_bytes = build_ranges_bytes(unencrypted_ranges)
        footer_bytes = build_footer(tag8, final_nonce_int, ranges_bytes)

        frame_payload = bytearray()
        frame_payload.extend(ciphertext)
        frame_payload.extend(footer_bytes)

        output_stream.extend(len(frame_payload).to_bytes(4, 'big'))
        output_stream.extend(frame_payload)

        print(f" [+] Frame {frame_id:04d} | Cipher: {len(ciphertext):,} B | Footer: {len(footer_bytes)} B | Nonce: {final_nonce_int}")
        frame_id += 1

    elapsed_time = time.perf_counter() - start_time
    print(f"[*] Ciphertext generation time: {elapsed_time:.6f} seconds")
    
    with open("polyglot_h265.bin", "wb") as f:
        f.write(output_stream)

    print(f"[*] Complete. Generated {frame_id} frames.")

if __name__ == "__main__":
    main()