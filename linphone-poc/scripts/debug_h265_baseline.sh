#!/usr/bin/env bash
# Diagnostic harness: H.265 baseline rerun with key divergence.
#
# Purpose: confirm Linphone + Android (receiver A) + iPhone (receiver B) can complete
# a Group-Call E2EE conference at the H.265 codec level. We need this baseline
# OK before run_attack_h265_armed.sh — the paper §5.4 attack substitutes H.265 NALs,
# so the receivers must be on H.265 for the adversary video to render.
#
# Same topology as debug_h264_phase1_key_divergence.sh except --codec h265
# on both focus and streamer.
#
# Expected (same key-divergence baseline, but H.265):
#   receiver A (Android): T+0..20 OK, T+20s onward video STOPS / breaks
#                    (receiver A stuck on K_initial; sender now sends with K_new)
#   receiver B (iPhone) : video CONTINUES through the rotation
#
# If either receiver fails to render H.265 at all (codec negotiation /
# hardware decoder issue), pause here — the primary attack demonstration won't be
# meaningful and we may need to fall back to H.264 + re-encoded adversary.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

ARM_FILE=/tmp/poc_blocklist_arm.flag

pkill -9 -f "streamer" 2>/dev/null || true
sleep 1
rm -f /tmp/focus.log /tmp/sender.log build/focus.uri "$ARM_FILE"

# shellcheck disable=SC1091
source build/envrc

EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" \
EKT_NOTIFY_BLOCKLIST_ARM_FILE="$ARM_FILE" \
python -m streamer.focus \
    --sip-uri "${SIP_FOCUS_URI}" \
    --sip-password-file .sip-password-focus \
    --codec h265 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "focus ready (codec=h265, blocklist=${SIP_RECV_A_USER}, arm_file=$ARM_FILE): $(cat build/focus.uri)"

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
    --rotate-arm-file "$ARM_FILE" \
    --log-level INFO > /tmp/sender.log 2>&1 &
disown

cat <<EOF

=========================================================================
  Diagnostic — H.265 baseline (hook NOT injected)
=========================================================================

  Answer the call on receiver A (Android) AND receiver B (iPhone). For the first
  ~20 seconds, both should see the H.265 video stream normally.

  At T+20s, key rotation fires and receiver A drops. Expected:
    - receiver A (Android): video STOPS / breaks after T+20 s
    - receiver B (iPhone):  video CONTINUES (may have iPhone-side stutter
                       similar to baseline H.264, that's OK)

  If EITHER receiver fails to render H.265 at all, we'll need to fall back
  to H.264 + re-encoded adversary content.

  Verify with:
    grep -E 'm=video|H265|H264|profile' /tmp/sender.log | head
    grep -E 'PoC ATTACK|EKT \(just selected\)' /tmp/focus.log

  Run for ~50 s total, then:
      pkill -9 -f streamer
=========================================================================
EOF
