import sys
import argparse
import binascii
import time
import os
import glob
from Crypto.Util.number import long_to_bytes,bytes_to_long
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES

from sage.all_cmdline import *

load('gcm.sage')

parser = argparse.ArgumentParser(description="Batch process polyglots.")
parser.add_argument('-d', '--dir', required=True, help="Input directory (e.g., padded_frames)")
parser.add_argument('-o', '--outdir', required=True, help="Output directory (e.g., cipher_frames)")
parser.add_argument('-k', '--keys', nargs=2, required=True)
parser.add_argument('-n', '--nonce', required=True)
parser.add_argument('-a', '--additional_data', required=True)
args = parser.parse_args()

in_dir = args.dir
out_dir = args.outdir
key1, key2 = [unhexlify(k) for k in args.keys]
nonce = unhexlify(args.nonce)
base_additional_data = unhexlify(args.additional_data)

os.makedirs(out_dir, exist_ok=True)
frames = sorted(glob.glob(os.path.join(in_dir, "*.bin")))

start_time = time.perf_counter()

# Convert base nonce to integer for sequential incrementation
base_nonce_int = int.from_bytes(nonce, 'big')

for seq_num, fn in enumerate(frames):
    with open(fn, "rb") as f:
        fdata = f.read()

    # Derive unique nonce for the current frame
    current_nonce = (base_nonce_int + seq_num).to_bytes(12, 'big')
    additional_data = base_additional_data

    # Encrypt with the target key to generate base ciphertext
    cipher = AES.new(key2, AES.MODE_GCM, nonce=current_nonce)
    _ = cipher.update(additional_data)
    target_ciphertext, _ = cipher.encrypt_and_digest(fdata)

    ciphertext = target_ciphertext
    original_ct_len = len(ciphertext)

    if original_ct_len % 16 > 0:
        padding_needed = 16 - original_ct_len % 16
        ciphertext += b"\0" * padding_needed
        original_ct_len += padding_needed

    ciphertext += b"\0" * 16
    final_ct_len = len(ciphertext)

    if len(additional_data) % 16 > 0:
        additional_data += b"\0" * (16 - len(additional_data) % 16)

    num_ad_blocks = len(additional_data) // 16
    ad_blocks = [additional_data[i*16 : i*16 +16] for i in range(num_ad_blocks)]

    num_ct_blocks = final_ct_len // 16
    ct_blocks = [ciphertext[i*16 : i*16 +16] for i in range(num_ct_blocks)]

    correction_index = num_ad_blocks + num_ct_blocks - 1

    # Compute GCM polyglot correction block to force tag collision
    ad_blocks, ct_blocks, tag_16byte = gcm_1block(key1, key2, current_nonce,
        correction_index,
        num_ct_blocks, ct_blocks,
        num_ad_blocks, ad_blocks)

    final_ciphertext = b''.join(ct_blocks)
    tag = tag_16byte[:8]

    # Format output: [SeqNum(4)] + [Tag(8)] + [Ciphertext]
    seq_bytes = seq_num.to_bytes(4, 'big')
    out_path = os.path.join(out_dir, os.path.basename(fn))
    with open(out_path, "wb") as f:
        f.write(seq_bytes + tag + final_ciphertext)

end_time = time.perf_counter()
print(f"\n[+] Processed {len(frames)} frames in {end_time - start_time:.2f} seconds.")