# DAVE Protocol AES-GCM Polyglot PoC

This repository contains a Proof of Concept (PoC) demonstrating a Polyglot attack exploiting the Lack of Key Commitment in AES-GCM, specifically targeting End-to-End Encryption (E2EE) protocols like DAVE.

By providing two different H.265 video streams and two distinct encryption keys, this PoC generates a single ciphertext. When decrypted with either key, the ciphertext successfully passes MAC verification and renders as a completely different, valid video.

## Quick Demo
For a quick demonstration of the results, please watch `Playback.mp4`. This video clearly shows how a single ciphertext renders completely different, valid videos for recipients depending on the encryption key they hold. 
If you wish to understand the detailed implementation, you can review the source code and verify the PoC yourself by following the instructions below.

## Overview

This PoC provides two implementation patterns:

1. **Full-Encryption Version (ENV-less)**:
   Encrypts the entire payload without any unencrypted Additional Authenticated Data (AAD). This pattern is ideal for verifying the codec-level integrity of the polyglot stream using local environments like GStreamer.

2. **Header-Unencrypted Version (ENV-inclusive)**:
   Complies strictly with the DAVE protocol specifications by leaving the H.265 Filler Data (ENV header) unencrypted as AAD. This pattern is designed for browser-based simulation testing via WebRTC's Insertable Streams API (`index.html`).

## Environment Setup

To run this PoC, you need a mathematical/cryptographic environment to generate the ciphertext, and a media processing environment for decryption and playback. Please set up the following using your OS package manager (e.g., `apt` for Ubuntu, `brew` for macOS) and `pip`:

* **Supported OS**: 
  * macOS / Linux
* **Dependencies & Tools**:
  * **SageMath**: Required for calculating the GHASH collisions during polyglot payload generation.
  * **Python 3.x**: Required for running the decryption script and the local HTTP server. The `pycryptodome` library must be installed (`pip install pycryptodome`).
  * **GStreamer**: Required for decoding and playing the H.265 stream via local UDP (for the Full-Encryption verification). Ensure you have the `good`, `bad`, `base`, and `libav` plugin sets installed.
  * **FFmpeg** (Optional but recommended): Useful for converting standard video files into raw H.265 streams for testing.

## Repository Structure

* `gcm.sage`, `util.sage`: Core GHASH collision calculation engine and utilities for AES-GCM.
* `notENV_h265.sage`: Polyglot generator script for the Full-Encryption (ENV-less) version.
* `notENV_decrypt.py`: Decryptor and clean-stream extraction script for the ENV-less version.
* `rtc_h265.sage`: Polyglot generator script for the Header-Unencrypted (ENV-inclusive) version.
* `index.html`: Browser-based PoC to verify the playback of the ENV-inclusive payload via WebRTC.
* `Playback.mp4`: A video recording demonstrating a successful playback in the WebRTC-simulated environment.
*  sample/: Directory containing sample files for verification.
    *  video1.mp4 / video2.mp4: Sample videos in MP4 format.
    *  video1.h265 / video2.h265: Sample videos converted to raw H.265 format.

> **Note:** `gcm.sage` and `util.sage` are adapted from the reference implementation by Albertini et al., *"How to Abuse and Fix Authenticated Encryption Without Key Commitment"* (USENIX Security 2022), available at https://github.com/kste/keycommitment (MIT License, © 2020 kste). We modified them for this PoC.
---

## Execution Steps

Before starting, prepare two H.265 video files for testing (e.g., `video1.h265` and `video2.h265`).
Alternatively, you can use the pre-converted sample files (`video1.h265` and `video2.h265`) provided in the `sample/` directory to quickly verify the PoC.

> **Tip: Preparing H.265 Video Files with FFmpeg**
> If you have standard video files (like `.mov` or `.mp4`), you can use `ffmpeg` to strip the audio and convert the video stream to a raw H.265 format suitable for this PoC.
> 
>     ffmpeg -i input.mov -c:v libx265 -an -f hevc video1.h265
> *(Note: The `-an` flag removes the audio track, as this PoC specifically targets video NAL units.)*

### Pattern 1: Full-Encryption (ENV-less) + GStreamer

This method encrypts the entire payload and verifies playback over a local UDP stream.

**1. Generate the Ciphertext**

    sage notENV_h265.sage -vA video1.h265 -vB video2.h265 \
        -k1 e8a17b3d9c4f2a5e6b8d1c0f3a2e5d4b \
        -k2 1f2e3d4c5b6a798897a6b5c4d3e2f100 \
        -n  7f8a9b0c1d2e3f4a5b6c7d8e

*Output File*: `polyglot_h265.bin`

**2. Decrypt and Extract Clean Streams**

    python3 notENV_decrypt.py \
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

---

### Pattern 2: Header-Unencrypted (ENV-inclusive) + WebRTC (Browser)

The ENV-less stream will fail to play in the browser-based WebRTC `index.html` environment due to the lack of unencrypted routing metadata. Therefore, use this pattern, which complies with the DAVE specification by leaving the header unencrypted.

**1. Generate the Ciphertext**

    sage rtc_h265.sage -vA video1.h265 -vB video2.h265 \
        -k1 e8a17b3d9c4f2a5e6b8d1c0f3a2e5d4b \
        -k2 1f2e3d4c5b6a798897a6b5c4d3e2f100 \
        -n  7f8a9b0c1d2e3f4a5b6c7d8e

*Output File*: `webrtc_polyglot_dave.bin`

**2. Start the Local Server**

    python3 -m http.server 8080

**3. Browser Verification**

**Recommended Browser:**  
This PoC has been tested primarily on Google Chrome.  
For the most stable behavior and compatibility with the WebRTC Insertable Streams API, using the latest version of Google Chrome is strongly recommended.

## Limitations and Known Issues

When running the playback test in the `index.html` (WebRTC) environment, the video does not always render successfully on the first attempt. In some runs the receiver's video fails to start.

**If the video fails to play, simply reload the browser and retry a few times until it succeeds.**

This behavior is **not a cryptographic flaw of the attack**. The validity of this PoC is supported by the following facts:

1. **Ciphertext Integrity**:
   In the GStreamer verification (Pattern 1), the generated payload plays reliably without any visual noise. This shows that the codec-level manipulations—specifically the AES-GCM GHASH correction block insertion and the H.265 start-code avoidance in the pseudo-random regions—function correctly.

2. **Cause of Failure (WebRTC Synchronization)**:
   The intermittent failure in WebRTC is unrelated to the polyglot structure. It stems from initial-keyframe (IDR) synchronization at the receiver: if the first injected frame is not delivered and decoded as a keyframe, the decoder has no reference frame to initialize from, and the sender stack in this PoC does not regenerate a keyframe on demand (no enforced keyframe cadence / PLI handling). Single-key AES-GCM streams sent through the same stack show comparable behavior, indicating the cause lies in the media transport rather than the attack.

Therefore, the variability in playback over the WebRTC route is an implementation artifact of this PoC's media stack. It does not undermine the validity of the attack or the threat demonstrated: that the lack of key commitment in AES-GCM can be exploited to construct a single ciphertext that decrypts into two completely different, perfectly valid videos depending on the key used.

For reference, a recording of a successful WebRTC playback is provided as `Playback.mp4`.