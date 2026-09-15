# poc-linphone — Linphone case study (Section 5)

This repository is the case-study artifact for **Section 5 (Linphone Group-Call E2EE)** of *Sowing Discord: Exploiting the Lack of Key Commitment in E2EE Group RTC* (IEEE S&P 2027). It builds three components, all targeting an unmodified consumer Linphone deployment (the official Android and iOS Linphone apps registered against the public `sip.linphone.org` free service):

See `Attack_Demo.mp4` in this directory for a recording of the attack.

1. a **send-only macOS CLI** (`streamer/`) that registers as
   `<sender-user>`, creates an EKT-based End-to-End-Encrypted group
   conference at `LinphoneConferenceSecurityLevelEndToEnd`, and pushes
   a looped local `.mp4`/`.mov` as the camera feed;
2. a **conference focus daemon** (`streamer/focus.py`) that registers
   as `<focus-user>` and runs an in-process EKT server with an
   `EKT_NOTIFY_BLOCKLIST` mechanism — this approximates the paper's
   §4.1 Anet adversary (TCP-delay-based key-state divergence) by
   silently dropping the EKT NOTIFY destined for one target receiver
   at rotation time, putting that receiver on the pre-rotation inner
   master key while every other receiver advances to the post-rotation
   key;
3. a **DYLD-injected hook** (`attack/hook/libattack_hook.dylib`,
   loaded into `sender`'s process) that rewrites every outgoing inner
   SRTP packet with a per-packet ambiguous AES-GCM ciphertext + tag
   constructed by the §5.3 + Appendix A algorithm, so the same packet
   authenticates under **both** the pre-rotation and post-rotation
   inner master keys and the two receivers decrypt it to different
   plaintexts.

The primary reproduction is `scripts/run_attack_h265_armed.sh`. It
demonstrates the §5.4 attack end-to-end: after one receiver is kept on
the pre-rotation key, the sender emits a single ambiguous SRTP
ciphertext/tag stream that authenticates under both the old and new
inner keys. Receiver A decrypts the same packets into
adversary-chosen H.265 frames, while receiver B accepts the packets at
SRTP but its decoder discards the pseudo-random plaintext.

The standalone cross-validation for paper Algorithm 2 + Appendix A is
shipped as a self-contained equivalence test
(`attack/hook/test_attack_crypto`, 6 deterministic vectors, bit-for-bit
against the checked-in reference dump) plus an end-to-end check
(`attack/hook/test_e2e_adversary`, 200 (NAL × target_len) combinations
where K_OLD decryption recovers the adversary NAL exactly and K_NEW
yields garbage that the H.265 parser rejects). These run without any
network or mobile device and verify the ciphertext construction even
if the live attack can't be reproduced for logistical reasons.

---

## Reproduction

Plan for roughly **30 minutes** in active time plus
**~10 minutes** of unattended SDK build. The primary live reproduction
is the H.265 armed attack harness:

```bash
./scripts/run_attack_h265_armed.sh
```

That script is the primary attack validation. It starts the focus,
starts the sender with `attack/hook/libattack_hook.dylib` injected,
arms ambiguous ciphertext substitution after the EKT rotation, and
logs the attack events to `/tmp/sender.log`.

After the one-time SDK build, anyone who only wants to validate the
cryptographic property without the full mobile setup can run the
cryptographic validation checks in `attack/hook/`.
The other `debug_*` scripts are troubleshooting harnesses for isolating
setup, codec, key-rotation, and hook-injection failures.

### Hardware / software requirements

| Component | Requirement |
|---|---|
| Sender + focus host | macOS on Apple Silicon (artifact verified on macOS 15.5, M-series). The cmake toolchain forces `-arch arm64`; x86 macOS is rejected by `scripts/build_linphone_sdk.sh`. |
| Mobile receivers | Two phones, one Android and one iOS, both on the same Wi-Fi band as the Mac. **Android**: install `https://download.linphone.org/releases/android/linphone-android-6.2.0.apk` (SHA-256 `dffdef0b0361caa05555ba2fef247d350d11c1bce157ecce5e1256da129d30bc`, 93 MB; the artifact was verified at exactly this release). **iOS**: install Linphone from the App Store; the artifact was verified against the App Store release current in early 2026 (matching the 6.2 line). Both phones must have **Settings → Security → End-to-end encryption (LIME)** enabled. |
| SIP service | Four free SIP accounts on the Linphone free SIP service, one each for the four logical roles below (sender, focus, two receivers). The harness scripts source `scripts/.env` to learn the your account names; copy `scripts/.env.example` to `scripts/.env` and edit the four `SIP_*_USER` lines before running anything. The accounts can be created from the web (no phone number, just an email confirmation) at `https://subscribe.linphone.org/register/email`; the same email address can be reused to register all four accounts. |
| Build dependencies | `cmake ninja yasm nasm doxygen ffmpeg` via Homebrew, plus Xcode Command-Line Tools (`xcode-select --install`). The build script does its own fail-fast precheck and prints the full list of anything missing. **Verified-against versions** (newer minor releases of each are expected to work): cmake 4.3.3, ninja 1.13.2, yasm 1.3.0, nasm 3.01, doxygen 1.17.0, ffmpeg 7.1; Apple clang 17.0.0 (CLT, `clang-1700.0.13.5`); macOS 15.5 (24F74); system Python 3.13.2 (the artifact requires `python3 >= 3.10`, which `pyproject.toml` enforces). |
| Linphone SDK upstream | Vendored under `third_party/linphone-sdk/` as a git subtree of the artifact-pinned upstream commit `7d5fe98a18ff7be2381656b600f880e3c49f5089` (master, 2025-12-23, between Linphone SDK 5.5.0-alpha and 5.5.0-beta). You don't fetch anything — the SDK source tree is part of this repository. The build applies the two patches under `patches/` to that tree at configure time and reverts them on exit unless `KEEP_PATCHES_APPLIED=1` is set, which the primary attack reproduction needs. (The SDK's own inner submodules — `bcg729`, `external/mbedtls`, `external/srtp`, etc. — are NOT carried by the subtree itself; see the "Inner submodules" note below.) |
| Python build deps | Installed into `build/venv/` from the pinned manifest `scripts/sdk-build-requirements.txt` (cython 3.2.5, wheel 0.47.0, pdoc 16.0.0, pystache 0.6.8, six 1.17.0). The project itself has no Python runtime dependencies (`pyproject.toml` lists none — pylinphone is supplied by the SDK build). |
| Disk | ~3 GB for the Linphone SDK build artefacts. |
| Time | ~25 min for the first SDK build; subsequent rebuilds with the hook layer only take seconds. |

### One-time setup

This setup is shared by the primary attack harness and all
troubleshooting harnesses. It builds the Linphone SDK (~25 min,
one-time), then runs a real conference between the sender (Mac), the
focus daemon (Mac), receiver A (Android) and receiver B (iOS).

#### One-time setup steps

**(a)** Create four SIP accounts at
`https://subscribe.linphone.org/register/email` (web registration —
just an email address, no phone number required; the same email
address can be reused for all four accounts). The four roles, with
the role identifier used by `scripts/.env`, are:

| Role identifier | What it does |
|---|---|
| `SIP_SENDER_USER` | The source of the conference (Mac CLI). The DYLD attack hook is injected into this process. |
| `SIP_FOCUS_USER`  | The conference focus daemon (Mac CLI). MUST be signed out of every phone. |
| `SIP_RECV_A_USER` | Receiver A on the Android Linphone app. The EKT_NOTIFY blocklist is keyed to this username, so this account is the one that gets stuck on the pre-rotation key. |
| `SIP_RECV_B_USER` | Receiver B on the iOS Linphone app — the control receiver that advances to the post-rotation key. |

Sign the recv_a account into the Android Linphone app and the recv_b
account into the iOS Linphone app. Sign the focus account *out of
every phone* (otherwise SIP forking will hijack the conference
INVITE).

**(b)** Tell the harness which usernames you just created. On the Mac:

```bash
cp scripts/.env.example scripts/.env
# edit scripts/.env and set SIP_SENDER_USER, SIP_FOCUS_USER,
# SIP_RECV_A_USER, SIP_RECV_B_USER to your account names.
```

`scripts/.env` is gitignored; the harness sources it before each run
so no username is hardcoded anywhere.

**(c)** Drop the SIP passwords into hidden files at the project root.
On the Mac terminal (`printf '%s'` is used to avoid appending a
trailing newline that would break the SIP REGISTER):

```bash
printf '%s' '<sender-password>' > .sip-password         && chmod 600 .sip-password
printf '%s' '<focus-password>' > .sip-password-focus   && chmod 600 .sip-password-focus
```

**(d)** Make sure both phones and the Mac are on the **same Wi-Fi band**
(a dual-band SSID with client-isolation hides the Mac from the phones).

**(e)** Build the Linphone SDK (one-shot, ~25 min on first run).
On the Mac terminal:

```bash
KEEP_PATCHES_APPLIED=1 ./scripts/build_linphone_sdk.sh
```

This builds the linphone-sdk source vendored under
`third_party/linphone-sdk/` out-of-tree into `./build/`. If you have a different SDK checkout (e.g. a snapshot that already has all the inner submodules pre-populated) you can export `SDK_SRC=/path/to/that/sdk` to override the default. The
`KEEP_PATCHES_APPLIED=1` flag keeps the two patches under `patches/`
applied after the build finishes (required for the armed attack;
harmless for the debug harnesses).

**Inner submodules.** The top-level linphone-sdk tree is in the
repository, but the upstream SDK declares 30 git submodules of its
own (`bcg729`, `bcmatroska2`, `external/mbedtls`, `external/srtp`,
`external/openh264`, …). The subtree merge does NOT carry those
inner submodules, so each submodule directory is initially empty.
The build script does NOT try to populate them in the vendored case
(no `.git` in `third_party/linphone-sdk/`), so before running the
build you must either:

* point `SDK_SRC` at a fully-populated linphone-sdk checkout
  elsewhere on disk, OR
* populate `third_party/linphone-sdk/`'s inner submodules
  out-of-band (e.g. `rsync -a /path/to/full-sdk/ third_party/linphone-sdk/`
  from any peer that has already done `git submodule update --init
  --recursive` on the upstream pinned commit).

**(f)** Build the DYLD hook and its local test binaries:

```bash
make -C attack/hook
```

This produces `attack/hook/libattack_hook.dylib`, which is required by
the primary attack harness below. If `make` complains with
`ERROR: linphone-sdk has not been built yet`, step (e) did not complete
on this checkout; run the SDK build once and then retry this step.

### Cryptographic validation (no devices, no network)

This validates the packet construction used by paper §5.3 and Appendix A independently of the live deployment. It uses the hook
test binaries built in step (f), so the SDK build and `make -C
attack/hook` must have completed first. The checks themselves take
well under a second to run.

```bash
cd attack/hook
make equiv                          # C hook vs reference vectors, 6/6
./test_e2e_adversary                # adversary-NAL round-trip,    200/200
```

Expected: both binaries print `[+] OK: ...` lines and exit 0. `make
equiv` runs the in-hook C implementation in
`attack/hook/attack_crypto.c` against the checked-in reference dump
`attack/hook/ambig_vectors.json` and asserts byte-for-byte agreement
on `(K_enc, S_session, nonce, ciphertext, tag)`. `test_e2e_adversary`
additionally builds the §5.3 AP-format plaintext, feeds it through
the ambiguous-ciphertext builder, then decrypts with mbedTLS AES-GCM
under each key, confirming that K_OLD decryption recovers the exact
adversary NAL bytes and K_NEW recovery does not parse as H.265.

### Run the attack

On the Mac terminal, run the primary harness:

```bash
./scripts/run_attack_h265_armed.sh
```

The script launches the focus daemon and the sender with the DYLD hook
armed, then prints a status banner.

**Now, the operator must do these steps in this order:**

1. **Pick up both phones**, with their screens unlocked, near the Mac.
2. The Android (`receiver A`) and the iPhone (`receiver B`) will both ring within
   a few seconds of the streamer printing `creating conference`.
3. **Answer the call on both phones** (tap the green answer button).
4. As soon as each phone's call screen comes up, look at the top of
   that screen. It must say **"End-to-End Encrypted"** (the verified
   label on Linphone Android 6.2.0; iOS shows the same string).
   - If it instead says **"Point-to-Point Encrypted"** or **"SRTP"**,
     the conference setup negotiated to a lower security tier and the
     §5.4 attack scenario does NOT apply to that call. Hang up and
     re-check (i) that the streamer was launched with
     `--security-level e2ee` (the harness scripts already do this), and
     (ii) that LIME / end-to-end encryption is **enabled** in the
     Linphone-app settings on both phones (Settings → Security →
     End-to-end encryption (LIME) → ON).
   - If it just says **"Waiting for encryption..."** for more than 10 s,
     the LIME / ZRTP exchange has stalled — see "Same Wi-Fi band" in
     step (c) above; retry after fixing the network.
5. For the first ~20 s, both phones show sender's looped content
   (bird on grass).
6. At T+20 s the streamer arms the EKT_NOTIFY blocklist, the focus
   stops the rotation NOTIFY destined for receiver A, and from then on
   sender's hook substitutes each outgoing inner SRTP packet with an
   ambiguous (ciphertext, tag) pair that authenticates under both
   the pre-rotation key receiver A still holds and the post-rotation key
   receiver B now uses. Expected observation:
   - **receiver A (Android)**: video transitions from sender's content
     (bird on grass) to the *adversary* content (a car with a bird
     in front of it), and continues to render briefly. This is the
     paper §5.3–5.4 visual effect — adversary-chosen video
     reaching receiver A despite the cryptographic boundary.
   - **receiver B (iPhone)**: video freezes / breaks. Bitrate metrics in
     the Linphone app still show several hundred kbps inbound
     (receiver B's libsrtp is *accepting* every packet — paper §5.3's
     "Lack of Key Commitment"), but the decoded plaintext is
     K_new-derived pseudo-random bytes that the H.265 decoder
     rejects.
7. After observing the effect, stop the run on the Mac terminal:
   ```bash
   pkill -9 -f streamer
   ```
8. Hang up the call on both phones.

After the run, inspect the hook's log on the Mac terminal:

```bash
grep -c "observer.protect\[ATTACK\]" /tmp/sender.log
grep    "mode=AP"                    /tmp/sender.log | head -5
grep -c "ssrc_map:"                  /tmp/sender.log
```

`observer.protect[ATTACK] N` should be hundreds — the count of packets
substituted. `mode=AP` packets are the §5.3 self-contained-frame
substitutions on sender's frame-end packets; the others use a single-NAL
substitution that the receivers' decoders silently discard. `ssrc_map`
lines show the SSRC-to-EKT-position table the hook latches at first
sight of each outgoing stream.

## Results

The primary run is successful when all of the following are true:

| Observation | Meaning |
|---|---|
| Both phones show **"End-to-End Encrypted"** before the attack window opens. | The live call is in the target Group-Call E2EE mode. |
| `/tmp/sender.log` contains hundreds of `observer.protect[ATTACK]` lines. | The hook is actively replacing outgoing inner-SRTP packets. |
| `/tmp/sender.log` contains `mode=AP` lines. | The validity-preserved H.265 packet form is being emitted. |
| Receiver A switches from the sender video to the adversary video after T+20 s. | The target receiver accepted the packet and rendered the adversary-chosen H.265 frame. |
| Receiver B freezes or breaks while still showing inbound bitrate. | The non-target receiver accepts SRTP but discards the resulting H.265 plaintext. |

## Troubleshooting

Use these harnesses only to isolate failures in the primary attack run.

| Symptom / question | Run | What it isolates |
|---|---|---|
| Need to verify the C crypto without phones or SIP | `cd attack/hook && make equiv && ./test_e2e_adversary` | Algorithm 2 / Appendix A ciphertext construction, AP plaintext construction, mbedTLS AES-GCM round-trip |
| Phones do not receive a stable H.265 baseline before the attack | `scripts/debug_h265_baseline.sh` | H.265 negotiation, MovieCam source, focus forwarding, receiver decoder support |
| Hook injection may be perturbing the baseline | `scripts/debug_h265_hook_observe.sh` | Same H.265 path with the DYLD hook loaded but observe-only; no packet substitution |
| Need to check the §5.1 key-state divergence separately | `scripts/debug_h264_phase1_key_divergence.sh` | EKT_NOTIFY blocklist, arm-file timing, receiver A stuck on the old key |
| Need to check rotation without suppressing any receiver | `scripts/debug_key_rotation_no_blocklist.sh` | Whether all participants survive an ordinary EKT rotation |
| Need an H.264 observe-only hook check | `scripts/debug_h264_hook_observe.sh` | Hook callbacks on the simpler H.264 path without armed substitution |
| Need the older blocklist-only harness for comparison | `scripts/debug_legacy_phase1_blocklist.sh` | Historical phase-1 blocklist run; kept for regression debugging |

If the SDK build stops while fetching Linphone submodules with
`Failed to connect to gitlab.linphone.org port 443`, re-run the same
build command. The build script is idempotent and skips submodules that
were already fetched. For a particularly flaky connection, increase the
retry budget:

```bash
SDK_SUBMODULE_TRIES=60 SDK_SUBMODULE_RETRY_DELAY=10 \
KEEP_PATCHES_APPLIED=1 ./scripts/build_linphone_sdk.sh
```

## Ethics and scope

Our Linphone experiments were conducted in an isolated local setup.
Linphone's public SIP server was used only for call-establishment
negotiation. The group-key management component relevant to the attack
was deployed by us, rather than relying on Linphone's production
group-key management infrastructure. The attacker and victim accounts
were operated from devices on the same local network, and all media
traffic, including audio and video packets carrying attack payloads,
remained confined to that local network.

This artifact is intended for controlled reproduction on
accounts and devices you own. It should not be pointed at third-party
SIP users, public conferences, or production deployments.

- The scripts require user-supplied SIP usernames in `scripts/.env`;
  no real account names are hardcoded.
- The default rotation URI uses the reserved `invalid` TLD and is not
  routable to a real user.
- The live harness calls only the two receiver accounts you configure.
- The focus, sender, and receivers should run on an isolated test setup
  or lab network.
- Do not commit `.sip-password`, `.sip-password-focus`, `scripts/.env`,
  `/tmp/*.log`, packet captures, or screenshots containing account
  identifiers.
- The repository includes only a PoC harness and does not provide an
  automated scanner or tooling for discovering vulnerable deployments.

## Reference

### Repository map

```
linphone-poc/
├── README.md                          (this file)
├── Attack_Demo.mp4 recording of the live attack
├── pyproject.toml
├── conf/linphonerc.example
├── patches/                           git-apply patches injected into linphone-sdk at build
│   ├── 0001-ekt-server-add-EKT_NOTIFY_BLOCKLIST-hook.patch
│   └── 0002-ms_srtp-attack-observer-hooks.patch
├── scripts/
│   ├── .env.example                   SIP account names (copy to .env and edit)
│   ├── common.sh                      sourced by run/debug harnesses — resolves SIP_*_URI
│   ├── build_linphone_sdk.sh          one-shot SDK + plugin build (applies + reverts patches)
│   ├── run_attack_h265_armed.sh       primary attack reproduction
│   ├── debug_h265_baseline.sh         H.265 baseline / receiver decoder check
│   ├── debug_h265_hook_observe.sh     H.265 hook observe-only check
│   ├── debug_h264_phase1_key_divergence.sh  §5.1 key-divergence check
│   ├── debug_h264_hook_observe.sh     H.264 hook observe-only check
│   ├── debug_key_rotation_no_blocklist.sh  ordinary EKT rotation check
│   └── debug_legacy_phase1_blocklist.sh    legacy blocklist-only check
├── plugins/msmoviecam/                custom mediastreamer2 webcam plugin
│   ├── CMakeLists.txt
│   └── src/msmoviecam.c
├── streamer/                          Python CLI
│   ├── cli.py                         argparse for the sender (incl. --rotate-after/--rotate-arm-file)
│   ├── config.py                      StreamerConfig dataclass
│   ├── core.py                        LinphoneCore lifecycle for the sender
│   ├── account.py                     modern Account API registration (+ lime spec)
│   ├── conference.py                  E2EE group-call create / join + invite_participants + trigger_rotation
│   ├── codecs.py                      H.264 enable, others off
│   ├── camera.py                      plugin env + MovieCam selector
│   └── focus.py                       self-hosted E2EE focus daemon
├── attack/                            §5.3 attack hook (C implementation + DYLD interposer)
│   ├── hook/                          libattack_hook.dylib + bit-for-bit tests
│   └── crypto/                        legacy Sage reference (not required to reproduce)
├── src-video/                         (.mp4 / .mov for sender, .h265 for adversary)
├── third_party/
│   └── linphone-sdk/                  vendored as git subtree (upstream commit 7d5fe98a18)
└── build/                             all build outputs
    ├── venv/                          project-local venv
    ├── sdk-build/                     linphone-sdk CMake build tree
    ├── sdk-install/                   linphone-sdk install tree + plugins
    │   └── Frameworks/
    │       ├── linphone.framework/Versions/A/Libraries/liblinphone_ektserver.so
    │       └── mediastreamer2.framework/Versions/A/Libraries/libmsmoviecam.so
    ├── plugin-build/
    ├── envrc                          sourced before running the CLIs
    └── focus.uri                      focus daemon's GRUU URI (written at focus startup)
```

### Runtime endpoints

By default we target the Linphone free service. To run against your own infrastructure (e.g. a self-hosted Flexisip), override:

| Endpoint | Default | Flag |
|---|---|---|
| SIP proxy | `sip:sip.linphone.org;transport=tls` | `--proxy` |
| Conference factory | `build/focus.uri` (our focus's GRUU) | `--conference-factory-uri-file` or `--conference-factory-uri` |
| LIME (X3DH) | `https://lime.linphone.org/lime-server/lime-server.php` | `--lime-server` |
| STUN | `stun.linphone.org` | `--stun-server` |
