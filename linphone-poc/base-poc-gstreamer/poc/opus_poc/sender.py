import socket
import time
import glob

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
FRAME_DIR = "cipher_frames"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
frames = sorted(glob.glob(f"{FRAME_DIR}/*.bin"))

print(f"Starting stream to {UDP_IP}:{UDP_PORT}...")

start_time = time.time()
for i, frame_file in enumerate(frames):
    with open(frame_file, 'rb') as f:
        packet = f.read()
    
    # Send payload to the target address via UDP
    sock.sendto(packet, (UDP_IP, UDP_PORT))
    
    # Calculate sleep duration to maintain exact interval and prevent time drift
    target_time = start_time + (i + 1) * 0.02
    sleep_duration = target_time - time.time()
    if sleep_duration > 0:
        time.sleep(sleep_duration)

print("Streaming finished.")