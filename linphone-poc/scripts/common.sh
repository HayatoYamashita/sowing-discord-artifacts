# Common helpers for the run/debug harnesses.
#
# Sourced (not executed). Resolves the reviewer's SIP account names from
# scripts/.env (which they copy from scripts/.env.example), then exports
# SIP_SENDER_URI, SIP_FOCUS_URI, SIP_RECV_A_URI, SIP_RECV_B_URI for use
# by the run scripts. No SIP username is provided as a default because
# any plausible username at sip.linphone.org may be a real account.

if [[ -z "${POC_DIR:-}" ]]; then
    echo "common.sh: callers must set POC_DIR before sourcing" >&2
    return 1 2>/dev/null || exit 1
fi

# shellcheck disable=SC1091
if [[ ! -f "${POC_DIR}/scripts/.env" ]]; then
    echo "common.sh: missing scripts/.env; copy scripts/.env.example and set reviewer-owned SIP usernames" >&2
    return 1 2>/dev/null || exit 1
fi
# shellcheck disable=SC1091
source "${POC_DIR}/scripts/.env"

: "${SIP_DOMAIN:=sip.linphone.org}"

for _name in SIP_SENDER_USER SIP_FOCUS_USER SIP_RECV_A_USER SIP_RECV_B_USER; do
    _value="${!_name:-}"
    if [[ -z "${_value}" || "${_value}" == \<* ]]; then
        echo "common.sh: ${_name} must be set in scripts/.env to a reviewer-owned SIP username" >&2
        return 1 2>/dev/null || exit 1
    fi
done

# Build full URIs.
SIP_SENDER_URI="sip:${SIP_SENDER_USER}@${SIP_DOMAIN}"
SIP_FOCUS_URI="sip:${SIP_FOCUS_USER}@${SIP_DOMAIN}"
SIP_RECV_A_URI="sip:${SIP_RECV_A_USER}@${SIP_DOMAIN}"
SIP_RECV_B_URI="sip:${SIP_RECV_B_USER}@${SIP_DOMAIN}"

export SIP_SENDER_USER SIP_FOCUS_USER SIP_RECV_A_USER SIP_RECV_B_USER SIP_DOMAIN
export SIP_SENDER_URI SIP_FOCUS_URI SIP_RECV_A_URI SIP_RECV_B_URI
