# Artifacts: TCP-Delay Key Desynchronization and Epoch-Transition Timing in Discord's DAVE Protocol

This repository contains the supporting artifacts for the experiments on inducing a temporary
key-state inconsistency in Discord's DAVE protocol via transient TCP delay, and on measuring the
epoch-transition detection latency used in the end-to-end timing budget.

The artifacts are released for Open Science / reproducibility. All recordings and logs were
produced using the authors' own accounts and devices, in a private call among those accounts only.
No attack was performed against Discord's production infrastructure or against any third-party user,
and no third-party data was collected.

The DevTools logs have been sanitized before release: account identifiers, connection IDs, key-ratchet pointers, SSRCs, and cryptographic material are pseudonymized or removed (see [Anonymization](#4-anonymization)). The reproduction procedure below is self-contained.

---

## 1. Repository contents

| File | Type | Role |
|------|------|------|
| `TCP_Delay_4s_Recovery.mp4` | Video | Delay tolerance at X = 4 s, TCP-only delay, with an epoch transition: temporary degradation followed by natural recovery |
| `TCP_UDP_Delay_Warning.mp4` | Video | X = 4 s, TCP+UDP delay (no TCP filtering), no join/leave: visible connection-quality degradation on the Discord UI, motivating the TCP-filtering strategy |
| `TCP_Delay_5s_Disconnect.mp4` | Video | X = 5 s, web client, TCP-only delay, with an epoch transition: disconnection followed by automatic reconnection |
| `davelog_A_sanitized.txt` | Text log | DevTools timing log of repeated `U_trig` join/leave — sample set A |
| `davelog_B_sanitized.txt` | Text log | DevTools timing log of repeated `U_trig` join/leave — sample set B |
| `README.md` | This file | Full reproduction procedure and artifact description |

A temporary degradation of the target's incoming media is present in all three videos while the
delay is active; the videos differ in what causes it and how it is perceived, as described below.

---

## 2. Description and role of each artifact

### 2.1 Video recordings

The videos record a live DAVE video call in which the target client (`U_tgt`) is subjected to
artificial inbound latency. They jointly demonstrate that a short TCP-only delay produces a
temporary, recoverable key-state inconsistency, and that delaying only TCP (and leaving the UDP
media path untouched) avoids the user-visible connection warnings that a TCP+UDP delay produces.

- `TCP_Delay_4s_Recovery.mp4` — X = 4 s, TCP-only delay, with an epoch transition.
  `U_tgt`'s inbound TCP flow is delayed by 4 s while UDP media is left untouched, and `U_trig`
  joins/leaves to force an MLS epoch transition. The target briefly cannot decrypt the other
  member's media (a short freeze during the window), but once the delay is released the client
  automatically processes the buffered MLS Commit and returns to the legitimate conversation with
  no disconnection. This is the core feasibility evidence: the key-state inconsistency can be
  induced and then cleanly resolved within the safe window.

- `TCP_UDP_Delay_Warning.mp4` — X = 4 s, TCP+UDP delay, no join/leave.
  The same 4 s delay is applied without TCP filtering, so the UDP media path is delayed as well,
  and no member joins or leaves (no epoch transition is triggered). In this case the call exhibits
  connection-quality degradation that is visible on the Discord interface: the connection-status
  antenna icon at the bottom-left of the Discord UI turns red, plainly indicating a poor
  connection. Contrasting `TCP_UDP_Delay_Warning.mp4` with `TCP_Delay_4s_Recovery.mp4` shows the advantage of the TCP-only filtering
  strategy: by sparing the UDP media stream, the interference does not raise the UI connection
  warning and stays perceptually indistinguishable from ordinary behavior.

- `TCP_Delay_5s_Disconnect.mp4` — X = 5 s, web client, TCP-only delay, with an epoch transition.
  `U_tgt` is opened in the browser (web) client and delayed by 5 s while `U_trig` triggers an
  epoch transition. With a delay of 5 s or more, the web client fails to process the delayed
  Commit in time, eventually drops the connection, and initiates an automatic reconnection. This
  delimits the safe delay window and motivates the conservative X ≤ 4 s bound for "any client".

Summary of the delay regimes observed across the experiments:

- X ≤ 4 s: temporary decryption freeze, then automatic recovery with no disconnect (`TCP_Delay_4s_Recovery.mp4`).
- 5 s ≤ X ≤ 10 s: web client disconnects and reconnects (`TCP_Delay_5s_Disconnect.mp4`); the desktop client instead
  recovers.
- X ≥ 10 s: other members discard the old key after the 10 s grace period, losing the ability to
  decrypt the still-delayed target's media.

### 2.2 Timing logs

`davelog_A_sanitized.txt` and `davelog_B_sanitized.txt` are Google Chrome DevTools console logs
captured on an existing-member client while a second account (`U_trig`) repeatedly joined and left
the call to force successive MLS epoch transitions. Each transition cycle records the MLS proposal
receipt, commit receipt/processing, new-epoch activation, and the per-sender key-ratchet additions.

These logs provide the measured value for the epoch-transition detection latency used in the
end-to-end timing budget. They also independently confirm two preconditions of the attack:
(i) each new key ratchet is added with `expiry: 10`, i.e. the previous-epoch key is retained for
10 s, and (ii) a client therefore holds old and new keys simultaneously during a window of at
least 10 s.

The two files are independent capture sessions; together they yield 39 epoch transitions. Data
were extracted and transformed for anonymity (see [Anonymization](#4-anonymization)); only the
lines relevant to epoch-transition timing are kept, and timestamps are expressed relative to the
start of each capture.

Measured result:

| Interval | min | mean | max |
|----------|-----|------|-----|
| MLS proposals received → new epoch active | 154 ms | 220 ms | 307 ms |
| MLS commit received → new epoch active | 52 ms | 98 ms | 197 ms |

(n = 39 epoch transitions across logs A and B.) The "proposals → active" figure is a conservative
upper bound because the captured client also acted as the committing member; a purely passive
member only incurs the "commit → active" portion. Either way the detection step is well under the
per-ciphertext generation cost and leaves a large margin within the 4 s window.

---

## 3. Complete reproduction procedure

This section is self-contained: it provides everything required to reproduce both the TCP-delay
experiments and the epoch-transition timing measurement.

### 3.1 Equipment and OS requirements

Three distinct Discord accounts on three devices, by role:

| Role | Purpose | OS requirement |
|------|---------|----------------|
| Target `U_tgt` | The client whose inbound traffic is delayed; runs the network simulator | Windows is required (the `clumsy` simulator is Windows-only). The Chrome web client is recommended so MLS epoch transitions can be observed via DevTools; the official desktop app can also be used to observe the platform-specific behavior at 5 s ≤ X ≤ 10 s. |
| Observer `U_i` | A control member that stays in the call (its media is what freezes/recovers on the target) | Any OS. Chrome web client recommended for DevTools log capture. |
| Trigger `U_trig` | Joins/leaves the call to force MLS epoch transitions | Any OS (e.g. a phone). |

The delay is always injected on `U_tgt`. Because `clumsy` is a Windows-only WinDivert-based tool,
the delayed machine (`U_tgt`) must run Windows; all other devices may run any OS. To capture the
DevTools timing logs, run the relevant client in Google Chrome (web version) and keep the DevTools
Console open.

### 3.2 Software

- Discord — web client (Google Chrome) and/or the official desktop application.
- clumsy v0.3 — network simulator for injecting inbound TCP latency on Windows.
- Google Chrome DevTools — to observe internal MLS/DAVE state-transition log messages
  (`Received MLS proposals`, `Received MLS commit`, `Successfully processed MLS commit … current
  epoch is N`, `Executing DAVE protocol transition`, `DAVE protocol state update`, and
  `Transitioning to new key ratchet: …, expiry: 10`).

### 3.3 clumsy configuration (on the Windows `U_tgt` machine)

| Parameter | Value |
|-----------|-------|
| Filter | `tcp and inbound` |
| Function | Lag (delay) |
| Lag time (delay X) | swept from a few hundred ms up to 15 s (key values: 4 s, 5 s, ≥10 s) |

For the TCP+UDP comparison (`TCP_UDP_Delay_Warning.mp4`), widen the filter so the media path is also delayed (e.g.
remove the `tcp` restriction and use `inbound` only) to reproduce the visible connection-quality
degradation that the TCP-only strategy avoids.

### 3.4 Step-by-step: TCP-delay experiments

DAVE delivers participant state-control messages (camera/mute toggles) and MLS key-update Commits
over TCP. To observe only key-exchange behavior, fix all participant states in advance.

1. Initialization. Establish a video call between `U_tgt` (Windows) and `U_i`. Turn on the camera
   of one member (`U_i`) and mute the microphones in advance; a single `U_i` camera being on is
   sufficient to observe the media freeze/recovery on the target. Do not toggle camera or mute
   again for the rest of the run, since those control messages also travel over TCP and would
   confound the measurement.
2. Stabilize. Wait until the `U_tgt`–`U_i` connection is stable and the video stream is flowing.
3. Inject delay. On the Windows `U_tgt` machine, start `clumsy` with the configuration in §3.3 for
   the desired delay X: 4 s, TCP-only for `TCP_Delay_4s_Recovery.mp4`; 5 s, TCP-only, web client for `TCP_Delay_5s_Disconnect.mp4`; 4 s,
   non-filtered TCP+UDP for `TCP_UDP_Delay_Warning.mp4`.
4. Trigger an epoch transition (for `TCP_Delay_4s_Recovery.mp4` and `TCP_Delay_5s_Disconnect.mp4` only). Under the delayed condition, have
   `U_trig` join (or leave) the call to make the server distribute an MLS Commit for the key
   update. 
   **Note on triggering epoch transitions:** Occasionally, `U_trig` joining or leaving the call might not trigger an epoch transition, possibly due to the member's state being cached. To reliably induce an epoch transition (and force the distribution of a Commit message), either wait a sufficient amount of time before re-joining/leaving, or, for the most guaranteed result, use a completely new account that has never joined that specific conversation before.
   For `TCP_UDP_Delay_Warning.mp4`, no join/leave is performed; the delay alone is used to observe the
   connection-quality side effect.
5. Observe and record. Watch playback on both screens and monitor the MLS/DAVE messages in Chrome
   DevTools to confirm the timing of key-update events. Record the screen.

Expected outcomes (these are what the videos show):

- X ≤ 4 s (TCP-only, with trigger): the target's incoming media freezes for X s, then the client
  automatically processes the delayed Commit and the call resumes with no disconnect (`TCP_Delay_4s_Recovery.mp4`).
- 5 s ≤ X ≤ 10 s (TCP-only, with trigger): the web client fails to process the delayed Commit,
  drops, and auto-reconnects (`TCP_Delay_5s_Disconnect.mp4`); the desktop client instead recovers.
- X ≥ 10 s: other members discard the old key after the 10 s grace, so they can no longer decrypt
  the still-delayed target's media.
- TCP+UDP delay, no filtering (`TCP_UDP_Delay_Warning.mp4`): a temporary connection-quality degradation appears, and
  the connection-status antenna icon at the bottom-left of the Discord UI turns red, unlike the
  TCP-only case where no such UI warning is shown.

### 3.5 Step-by-step: epoch-transition timing measurement (davelog A/B)

1. Establish a stable call among the fixed-state members and open Chrome DevTools → Console on an
   existing member.
2. Repeatedly have `U_trig` join and leave the call to generate successive MLS epoch transitions
   (each join or leave advances the epoch).
3. Let the DevTools Console accumulate the transition log lines, then export/save the console log
   to a text file.
4. For each transition cycle, compute the detection latency as the wall-clock difference between
   the first observation of the transition (`Received MLS proposals`) and the new epoch becoming
   active (`DAVE protocol state update`). The interval from `Received MLS commit` to
   `DAVE protocol state update` is the processing-only portion relevant to a passive member.
5. Aggregate across all cycles to obtain the min/mean/max reported in §2.2.

A single representative cycle (from `davelog_B_sanitized.txt`) looks like:

```
[t+00.000s] [UnifiedConnection] Attempting to create user U_1
[t+00.417s] [RTCConnection(C_1)] Received MLS proposals                      <- transition observed
[t+00.524s] [RTCConnection(C_1)] Received MLS commit for transition ID 18
[t+00.559s] (session.cpp) Successfully processed MLS commit; epoch is 19
[t+00.560s] (decryptor.cpp) Transitioning to new key ratchet: R_1, expiry: 10  <- old key kept 10 s
[t+00.580s] [DaveSessionManager] DAVE protocol state update {epochAuthenticator:<redacted>}  <- new epoch active
  => detection-to-ready (proposals -> state update) = 163 ms
```

---

## 4. Anonymization

The DevTools logs were processed before release so they can be shared safely:

- Discord account snowflake IDs → pseudonyms (`U_1`, `U_2`, …).
- RTC connection IDs → pseudonyms (`C_1`, …).
- Key-ratchet pointers → labels (`R_1`, …).
- RTP SSRC values → `<ssrc>`.
- MLS proposal/commit byte strings (ephemeral public keys, signatures, KeyPackages) → removed.
- `epochAuthenticator` values → `<redacted>`.
- Client build-hash filenames → generic names (`sentry.js`, `web.js`, `media.js`).
- Absolute timestamps → relative offsets (`t+ss.mmm`) from the start of each capture.

Only the log lines relevant to epoch-transition timing are retained. We verified that no raw
snowflake IDs, SSRCs, base64 authenticators, or build hashes remain in the released files. No
emails, usernames, IP addresses, ICE candidates, invite codes, tokens, or credentials were present
in the original captures.

## 5. Ethics

All experiments were conducted in a controlled, private setting using only the authors' own
accounts and devices. We did not attack Discord's production service or any third-party user, did
not access other users' data, and did not consume third-party resources beyond ordinary client
usage. The artifacts are provided solely to demonstrate feasibility and enable reproduction.
