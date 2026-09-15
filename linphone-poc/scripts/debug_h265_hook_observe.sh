#!/usr/bin/env bash
# Diagnostic harness: H.265 + hook OBSERVE-ONLY (no substitution).
#
# Purpose: bisect failures in run_attack_h265_armed.sh.
# This script differs from the primary attack in exactly one way: ATTACK_HOOK_ARM is
# UNSET, so the hook only observes and never overwrites packets.
#
# Outcomes:
#   - If receiver A+receiver B see video like debug_h265_baseline.sh → ARM=1 substitution
#     is what's killing the video pipeline (real bug in our hook).
#   - If they don't see video either → DYLD_INSERT itself is incompatible
#     with H.265 on macOS, independent of substitution. We'd then need to
#     audit what about the hook's load-time setup interferes with the
#     VideoToolbox H.265 encoder / MSMovieCam pipeline.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

HOOK_DYLIB="${POC_DIR}/attack/hook/libattack_hook.dylib"
HOOK_VIDEO="${POC_DIR}/src-video/video_01_main_1920x1440.h265"
ARM_FILE=/tmp/poc_blocklist_arm.flag

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
echo "[+] launching sender with libattack_hook.dylib (OBSERVE-ONLY, H.265)"

# OBSERVE-ONLY: ATTACK_HOOK_ARM is intentionally UNSET.
DYLD_INSERT_LIBRARIES="${HOOK_DYLIB}" \
ATTACK_HOOK_VIDEO="${HOOK_VIDEO}" \
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
  Diagnostic — H.265 + hook OBSERVE-ONLY
=========================================================================

  Answer the call on both phones. Expected (if hook is benign):
    same as debug_h265_baseline.sh — receiver A+receiver B see video, receiver A freezes at T+20s.

  If video doesn't render: the hook's mere presence (not ARM=1) breaks
  H.265 — investigate dyld load-time interference with VideoToolbox.

  Run ~40s, then:
      pkill -9 -f streamer

  Diagnostic:
      grep -c 'observer.protect\\[observe\\]' /tmp/sender.log    # >0 = video flowing
      grep -E 'MSMovieCam|Broken pipe|method index'             # ffmpeg pipeline state
=========================================================================
EOF
