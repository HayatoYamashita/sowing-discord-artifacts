import wave
import opuslib
import os

WAV_FILE = "test_48k.wav"
OUTPUT_DIR = "raw_frames"
FRAME_SIZE = 960
SAMPLE_RATE = 48000
CHANNELS = 1

os.makedirs(OUTPUT_DIR, exist_ok=True)
encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, 'voip')

with wave.open(WAV_FILE, 'rb') as wf:
    frame_idx = 0
    while True:
        # Read 1 frame of PCM data
        pcm_data = wf.readframes(FRAME_SIZE)
        if len(pcm_data) < FRAME_SIZE * 2:
            break

        # Encode to raw Opus payload
        opus_data = encoder.encode(pcm_data, FRAME_SIZE)
        
        with open(f"{OUTPUT_DIR}/frame_{frame_idx:04d}.bin", 'wb') as f:
            f.write(opus_data)
        frame_idx += 1

print(f"Extraction complete: {frame_idx} frames generated.")