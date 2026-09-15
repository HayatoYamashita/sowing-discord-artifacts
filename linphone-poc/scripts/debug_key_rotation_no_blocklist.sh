#!/usr/bin/env bash
# Diagnostic harness: rotation trigger check (blocklist OFF baseline).
#
# Scenario: start the focus without a blocklist so that sender + receiver A + receiver B
# all reach a state where they can receive the EKT. At T=20s the sender invites a dummy URI
# → the focus runs onAllowedParticipantListChanged → the EKT plugin does clearData +
# generateSSpi → requests all participants to re-publish + distributes the new EKT.
# Success is when the focus log shows "Allowed participant list ... updated. Participants must
# regenerate EKT."
#
# On the receiving side (receiver A/receiver B), video should briefly cut out and resume
# (= transition from K_initial to K_new).

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

pkill -9 -f "streamer" 2>/dev/null || true
sleep 1
rm -f /tmp/focus.log /tmp/sender.log build/focus.uri

# shellcheck disable=SC1091
source build/envrc

# Start the focus without a blocklist (testing the rotation trigger in isolation)
python -m streamer.focus \
    --sip-uri "${SIP_FOCUS_URI}" \
    --sip-password-file .sip-password-focus \
    --codec h264 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "focus ready: $(cat build/focus.uri)"

# Start the streamer with rotate-after 20s
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
    --log-level INFO > /tmp/sender.log 2>&1 &
    # Note: --rotate-uri defaults to sip:_poc_attack_dummy_DO_NOT_CALL@invalid
    # (RFC 6761 reserved TLD `invalid`, unroutable, cannot collide with any
    # real Linphone user). Override only if you have a specific need.
disown

echo ""
echo "streamer started. Answer the call on receiver A (Android) AND receiver B (iPhone)."
echo "Both will see video. At T+20s the rotation trigger fires."
echo "Wait 40 s total, then stop."
echo ""
echo "After stopping, inspect with:"
echo "  grep 'Allowed participant\\|generateSSpi\\|EKT selected\\|EKT sent to' /tmp/focus.log"
