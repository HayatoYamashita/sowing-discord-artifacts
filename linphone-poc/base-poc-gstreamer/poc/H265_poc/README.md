# LINPHONE Protocol AES-GCM Polyglot PoC

This repository contains a Proof of Concept (PoC) demonstrating a Polyglot attack exploiting the **Lack of Key Commitment** in AES-GCM, specifically targeting End-to-End Encryption (E2EE) protocols like LINPHONE.

By providing two different H.265 video streams and two distinct encryption keys, this PoC generates a single ciphertext. When decrypted with either key, the ciphertext successfully passes MAC verification and renders as a completely different, valid video.

## Overview

This PoC encrypts the entire payload without any unencrypted Additional Authenticated Data (AAD), and verifies the codec-level integrity of the polyglot stream locally via GStreamer.

## Environment Setup

To run this PoC, you need a mathematical/cryptographic environment to generate the ciphertext, and a media processing environment for decryption and playback. Please set up the following using your OS package manager (e.g., `apt` for Ubuntu, `brew` for macOS) and `pip`:

* **Supported OS**: 
  * macOS / Linux
* **Dependencies & Tools**:
  * **SageMath**: Required for calculating the GHASH collisions during polyglot payload generation.
  * **Python 3.x**: Required for running the decryption script and the local HTTP server. The `pycryptodome` library must be installed (`pip install pycryptodome`).
  * **GStreamer**: Required for decoding and playing the H.265 stream via local UDP. Ensure you have the `good`, `bad`, `base`, and `libav` plugin sets installed.
  * **FFmpeg** (Optional but recommended): Useful for converting standard video files into raw H.265 streams for testing.

## Repository Structure

* `gcm.sage`, `util.sage`: Core GHASH collision calculation engine and utilities for AES-GCM.
* `polyglot_h265.sage`: Polyglot generator script.
* `polyglot_decrypt.py`: Decryptor and clean-stream extraction script.

---

## Execution Steps

Before starting, prepare two H.265 video files for testing (e.g., `video1.h265` and `video2.h265`).

> **Tip: Preparing H.265 Video Files with FFmpeg**
> If you have standard video files (like `.mov` or `.mp4`), you can use `ffmpeg` to strip the audio and convert the video stream to a raw H.265 format suitable for this PoC.
> 
>     ffmpeg -i input.mov -c:v libx265 -an -f hevc video1.h265
> *(Note: The `-an` flag removes the audio track, as this PoC specifically targets video NAL units.)*

**1. Generate the Ciphertext**

    sage polyglot_h265.sage -vA video1.h265 -vB video2.h265 \
        -k1 e8a17b3d9c4f2a5e6b8d1c0f3a2e5d4b \
        -k2 1f2e3d4c5b6a798897a6b5c4d3e2f100 \
        -n  7f8a9b0c1d2e3f4a5b6c7d8e

*Output File*: `polyglot_h265.bin`

**2. Decrypt and Extract Clean Streams**

    python3 polyglot_decrypt.py \
        -i polyglot_h265.bin \
        -k1 e8a17b3d9c4f2a5e6b8d1c0f3a2e5d4b \
        -k2 1f2e3d4c5b6a798897a6b5c4d3e2f100

*Output Files*: `decrypted_key1.h265`, `decrypted_key2.h265`

**3. Playback via GStreamer**
Open two terminal windows to run the receiver (listener) and the sender simultaneously.

*Receiver Terminal (Listen):*

    gst-launch-1.0 udpsrc port=5000 caps="application/x-rtp, media=video, clock-rate=90000, encoding-name=H265" ! rtph265depay ! avdec_h265 ! autovideosink

*Sender Terminal (Send Key1 OR Key2 video):*

    # To play the Key1 video:
    gst-launch-1.0 filesrc location=decrypted_key1.h265 ! h265parse ! rtph265pay ! udpsink host=127.0.0.1 port=5000

    # To play the Key2 video:
    gst-launch-1.0 filesrc location=decrypted_key2.h265 ! h265parse ! rtph265pay ! udpsink host=127.0.0.1 port=5000
