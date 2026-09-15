import socket
import pyaudio
import opuslib
import argparse
from Crypto.Cipher import AES

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
SAMPLE_RATE = 48000
CHANNELS = 1
FRAME_SIZE = 960

NONCE = bytes.fromhex("0c1b2a3d4e5f6789abcd0101")
AAD = bytes.fromhex("C0FFEE1234567890ABCDEF0123456789")

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--key', required=True, help="Decryption key (hex)")
args = parser.parse_args()
key = bytes.fromhex(args.key)

p = pyaudio.PyAudio()
stream = p.open(format=pyaudio.paInt16, channels=CHANNELS, rate=SAMPLE_RATE, output=True)
decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on port {UDP_PORT} with key {args.key[:8]}...")

try:
    while True:
        packet, addr = sock.recvfrom(4096)
        
        # Ensure minimum packet length (SeqNum + Tag)
        if len(packet) < 12:
            continue
            
        seq_bytes = packet[:4]
        tag = packet[4:12]
        ciphertext = packet[12:]
        
        # Reconstruct the nonce from the sequence number
        seq_num = int.from_bytes(seq_bytes, 'big')
        base_nonce_int = int.from_bytes(NONCE, 'big')
        current_nonce = (base_nonce_int + seq_num).to_bytes(12, 'big')
        
        try:
            # Authenticate and decrypt the payload
            cipher = AES.new(key, AES.MODE_GCM, nonce=current_nonce, mac_len=len(tag))
            cipher.update(AAD)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("MAC Verification Failed")
            continue
            
        try:
            # Decode Opus payload and handle codec parsing errors (polyglot behavior)
            pcm_data = decoder.decode(plaintext, FRAME_SIZE)
            stream.write(pcm_data)
        except opuslib.OpusError as e:
            print(f"Decode Error: {e}")
            plc_data = decoder.decode(b'', FRAME_SIZE)
            stream.write(plc_data)

except KeyboardInterrupt:
    print("\nStopping...")
finally:
    stream.stop_stream()
    stream.close()
    p.terminate()