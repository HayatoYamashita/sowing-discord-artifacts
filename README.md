# Sowing Discord: Exploiting the Lack of Key Commitment in E2EE Group RTC

Research artifacts for the IEEE S&P 2027 paper.

**Hayato Yamashita** (The University of Osaka),
**Hayato Kimura** (NICT / The University of Osaka),
**Atsushi Tanaka** (The University of Osaka),
**Takanori Isobe** (The University of Osaka)

---

## Overview

The paper shows that the lack of key commitment in AES-GCM can be exploited
in end-to-end encrypted group real-time communication. A malicious
participant broadcasts a single ciphertext that authenticates under two
different receiver keys and decodes into different media for different
receivers. The attack proceeds in two phases: a network-level TCP delay
induces a temporary receiver-dependent key state, and a codec-aware
ambiguous ciphertext is then transmitted within that window.

These artifacts cover both phases against Discord's DAVE protocol, and a
fully integrated end-to-end attack against Linphone group-call E2EE.

## Contents

| Directory | Paper section | What it contains |
|---|---|---|
| [`demonstration/`](demonstration/) | Sec. 4.1, 4.3.2, 4.3.3 | Screen recordings and DevTools logs for the TCP-delay experiments on real Discord clients, and the epoch-transition timing measurements behind Table 2 |
| [`opus-poc/`](opus-poc/) | Sec. 4.2.1, Algorithm 1 | Generation and playback of ambiguous Opus ciphertexts; the target hears adversary-chosen audio, other receivers hear interrupted noise |
| [`h265-poc/`](h265-poc/) | Sec. 4.2.2, Algorithm 2 | Generation and playback of the ENV-based H.265 polyglot; two receivers render two different valid videos from one ciphertext, over a WebRTC path using the DAVE frame format |
| [`linphone-poc/`](linphone-poc/) | Sec. 5 | Fully integrated end-to-end attack against Linphone group-call E2EE, using unmodified Linphone apps on Android and iOS |

Each directory has its own README with complete setup and reproduction
instructions.

## Where to start

- To see the results without setting anything up:
  `h265-poc/Playback.mp4`, `demonstration/TCP_Delay_4s_Recovery.mp4`,
  and `linphone-poc/Attack_Demo.mp4`.
- To verify the cryptographic construction with no network or devices:
  `linphone-poc/attack/hook/` (`make equiv`, `./test_e2e_adversary`).
- To reproduce the DAVE-format constructions: `opus-poc/` and `h265-poc/`.
- To reproduce the full end-to-end attack: `linphone-poc/`.

## Requirements at a glance

| Directory | OS | Notable requirements |
|---|---|---|
| `demonstration/` | Windows (target) + any | Discord accounts, clumsy v0.3, Chrome DevTools |
| `opus-poc/` | macOS / Linux | SageMath, Python 3.8+, FFmpeg, opuslib, PyAudio |
| `h265-poc/` | macOS / Linux | SageMath, Python 3.x, GStreamer, Chrome |
| `linphone-poc/` | macOS (Apple Silicon) | Android + iOS devices, 4 SIP accounts, ~3 GB disk, ~25 min build |

## Responsible disclosure

All findings were reported to the affected vendors before publication.
Discord accepted the report as a valid vulnerability and awarded a bug
bounty; Linphone confirmed the analysis and plans to bind a verified key
identifier into the SRTP Master Key Identifier mechanism. See the
Responsible Disclosure section of the paper for the full timeline.

**At the time of release, the mitigations are not yet deployed.** These
artifacts contain working attack code. They are provided for research and
evaluation purposes only. Do not run them against any service, account, or
user you do not control.

## Ethics

All experiments were conducted in controlled, private settings using only
the authors' own accounts and devices. No attack was performed against any
production service or third-party user, and no third-party data was
collected. Logs included in `demonstration/` have been sanitized;
identifiers and cryptographic material are pseudonymized or removed.

## License

[MIT](LICENSE).

`gcm.sage` and `util.sage` in `opus-poc/` and `h265-poc/` are adapted from
the reference implementation accompanying Albertini et al., *"How to Abuse
and Fix Authenticated Encryption Without Key Commitment"* (USENIX Security
2022), available at https://github.com/kste/keycommitment
(MIT License, (c) 2020 kste).

`linphone-poc/third_party/linphone-sdk/` is a vendored copy of the Linphone
SDK and remains under its own upstream license. Its per-directory
`.gitignore` files were renamed to `.gitignore.upstream` so that the full
source tree is carried by this repository; their contents are unchanged.

## Citation

```bibtex
@inproceedings{yamashita2027Discord,
  author    = {Hayato Yamashita and Hayato Kimura and Atsushi Tanaka and Takanori Isobe},
  title     = {Sowing Discord: Exploiting the Lack of Key Commitment in {E2EE} Group {RTC}},
  booktitle = {2027 IEEE Symposium on Security and Privacy (SP)},
  year      = {2027}
}
```
