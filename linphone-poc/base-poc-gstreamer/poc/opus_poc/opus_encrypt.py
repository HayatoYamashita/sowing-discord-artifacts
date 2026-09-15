import os
import glob
import subprocess

os.makedirs("padded_frames", exist_ok=True)
os.makedirs("cipher_frames", exist_ok=True)
frames = sorted(glob.glob("raw_frames/*.bin"))

print("1. Preparing Opus headers (Code 0 -> Code 3)...")
for f in frames:
    with open(f, 'rb') as file:
        orig_data = file.read()
    
    # Modify Opus TOC byte and inject padding
    orig_toc = orig_data[0]
    new_toc = (orig_toc & 0xFC) | 0x03
    v_byte = 0x41
    
    L_prime = len(orig_data) + 2
    pad_needed = 16 - (L_prime % 16) if L_prime % 16 != 0 else 0
    K = pad_needed + 16
    
    new_packet = bytes([new_toc, v_byte, K]) + orig_data[1:]
    
    filename = os.path.basename(f)
    with open(f"padded_frames/{filename}", 'wb') as out_file:
        out_file.write(new_packet)

print(f"2. Launching SageMath for {len(frames)} frames...")

# Execute SageMath script for AES-GCM encryption
cmd = [
    "sage", "mitra_gcm.sage",
    "-d", "padded_frames",
    "-o", "cipher_frames",
    "-k", "a4c9b7f1d0e325869b3a2c1d4f5e6789", "210f3e5c7a9b8d6f4b1a3c5e7d9f0e1d",
    "-n", "0c1b2a3d4e5f6789abcd0101",
    "-a", "C0FFEE1234567890ABCDEF0123456789"
]
subprocess.run(cmd)