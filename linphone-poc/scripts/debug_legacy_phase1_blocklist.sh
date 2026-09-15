#!/usr/bin/env bash
# Legacy diagnostic harness: start the focus with EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" and
# invite both receiver A and receiver B from the sender into an E2EE conference. A test harness
# for observing that the EKT NOTIFY to receiver A is suppressed and the key is not updated on
# receiver A's side.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

# Clear processes & logs
pkill -9 -f "streamer" 2>/dev/null || true
sleep 1
rm -f /tmp/focus.log /tmp/sender.log build/focus.uri

# venv + DYLD env
# shellcheck disable=SC1091
source build/envrc

# Start the focus with the blocklist enabled
EKT_NOTIFY_BLOCKLIST="${SIP_RECV_A_USER}" \
python -m streamer.focus \
    --sip-uri "${SIP_FOCUS_URI}" \
    --sip-password-file .sip-password-focus \
    --codec h264 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

# Wait for the focus to finish starting up
until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "focus ready: $(cat build/focus.uri)"

# Start the streamer (sender) inviting both receiver A and receiver B
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
    --log-level INFO > /tmp/sender.log 2>&1 &
disown

echo ""
echo "streamer started. Now answer the call on:"
echo "  receiver A (Android, expected: NO video — key suppressed)"
echo "  receiver B (iPhone,  expected:   video OK — normal flow)"
echo ""
echo "Wait ~30 s, then stop with:  pkill -9 -f streamer"
echo ""
echo "After stopping, inspect with:"
echo "  grep 'PoC ATTACK' /tmp/focus.log"
echo "  grep -E 'EKT sent to|EKT selected|EKT enabled by no key' /tmp/focus.log /tmp/sender.log"
