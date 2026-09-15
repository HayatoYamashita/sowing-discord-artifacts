# PoC: AES-GCM Key Commitment Attack on Opus/RTC

This repository contains a Proof of Concept (PoC) demonstrating the lack of key commitment in AES-GCM within real-time communication (RTC / VoIP) protocols.

By crafting a ciphertext that generates the same authentication tag (MAC) for two different encryption keys, this PoC reproduces a behavior where the specific target (the intended recipient) plays normal Opus audio, while other participants play interrupted noise due to Opus decoding errors.

## Prerequisites

This PoC uses SageMath for mathematical operations (polynomial operations over Galois fields) and Python for audio processing and networking. It can be executed on macOS or Linux.

*   **OS:** macOS / Linux
*   **Audio Backend:** CoreAudio / ALSA / PulseAudio (for PyAudio playback)
*   **Tools & Frameworks:**
    *   Python 3.8+
    *   SageMath 9.x+
    *   FFmpeg (used for audio sample rate conversion)
*   **Python Dependencies:**
    *   `pycryptodome` (AES encryption)
    *   `opuslib` (Opus codec encode/decode)
    *   `pyaudio` (Real-time audio playback)

## Repository Structure

| File | Description |
| :--- | :--- |
| `extract_frames.py` | Reads a WAV file (PCM), encodes it, and splits it into raw 20ms Opus frames. |
| `opus_encrypt.py` | Modifies the Opus frame TOC headers to allocate padding space, and executes `mitra_gcm.sage` to perform encryption. |
| `mitra_gcm.sage` | Derives the Nonce for each frame and uses `gcm.sage` to generate ciphertexts that can be decrypted by multiple keys. |
| `gcm.sage` | The core logic of the attack. Solves linear equations to compute a correction block that forces AES-GCM authentication tags (GHASH) to collide across multiple keys. |
| `util.sage` | Utilities for AES block encryption and GF(2^128) polynomial conversions in SageMath. |
| `sender.py` | Reads the generated ciphertexts and streams them via UDP. |
| `receiver.py` | Receives UDP packets, performs AES-GCM MAC verification and decryption with a specified key, and plays the Opus decoded result in real-time. |

## Usage & Workflow

Follow the steps below to prepare the audio data, generate the attack payloads, and verify the differing behaviors on the receiving ends.

**Note on repeated experiments:** 
If you run experiments repeatedly with different audio files, make sure to delete the `cipher_frames/`, `padded_frames/`, and `raw_frames/` directories beforehand to clear any data from previous runs.

### 1. Prepare the Audio File
Prepare an arbitrary WAV file (`test.wav`) and convert it to the Opus standard: 48kHz sample rate, mono, 16-bit PCM.

**Sample Files:** 
We have provided `test.wav`, `test2.wav`, and `test3.wav` in the `sample/` folder. These are audio files of varying lengths recorded using an AI (ChatGPT) text-to-speech feature. You can directly use these files to verify the PoC.

    ffmpeg -i test.wav -ar 48000 -ac 1 -c:a pcm_s16le test_48k.wav

### 2. Extract Opus Frames
Reads the WAV file and splits it into 20ms Opus payloads.
Upon success, multiple `.bin` files will be output to the `raw_frames/` directory.

    python3 extract_frames.py

### 3. Generate Ciphertexts (Encryption & Tag Calculation)
Adds padding space to the Opus headers, then calls SageMath to calculate the AES-GCM collisions and generate the ciphertexts.
Once completed, the encrypted packets will be output to the `cipher_frames/` directory.

    python3 opus_encrypt.py

### 4. Setup Receivers (Behavior Verification)
To verify the attack, open two separate terminals and start the receivers with different keys.

**Terminal A: Target Environment (Key expected to play normally)**

    python3 receiver.py -k 210f3e5c7a9b8d6f4b1a3c5e7d9f0e1d

**Terminal B: Other Participant Environment (Key expected to cause decode errors)**

    python3 receiver.py -k a4c9b7f1d0e325869b3a2c1d4f5e6789

### 5. Send Packets
In a new terminal, run the sender script to stream the packets in `cipher_frames/` to `127.0.0.1:5005`.

    python3 sender.py

### Expected Results
Once the stream starts, both receivers in Terminal A and Terminal B will **successfully verify the MAC**.
However, because the decrypted plaintext padding structure is interpreted differently, the following behavioral difference occurs:

*   **Target Environment (-k 210f...):** The padding is ignored correctly, and the audio plays normally.
*   **Other Participant (-k a4c9...):** Interpreted as an invalid byte sequence violating the Opus codec specifications, it outputs `Decode Error ...` and generates interrupted noise.

## Disclaimer & Implementation Notes

This repository is intended strictly as a Proof of Concept (PoC) for the attack. To simplify the verification process, several parameters are hardcoded in the source code:

*   Input/output directory names (`raw_frames`, `cipher_frames`) and base filenames.
*   AES-GCM encryption keys (Key1, Key2), base Nonce, and Additional Authenticated Data (AAD).
*   UDP communication IP address (`127.0.0.1`) and port number (`5005`).
*   Magic numbers such as the Opus sample rate and frame size.
