from __future__ import annotations

import logging
import signal
import time
from contextlib import contextmanager

import linphone

log = logging.getLogger(__name__)

# Strong refs to keep Python callbacks alive while the Core is up — Cython
# bindings store the listener via weak reference, so the Python wrapper must
# outlive the Core externally.
_LIVE_LISTENERS: list = []


@contextmanager
def linphone_core(rc_path: str | None = None, *, lime_server_url: str | None = None):
    """Create + run a LinphoneCore for the duration of the with-block.

    Wires up the small set of state callbacks that this CLI cares about
    (registration, call state, conference state). The core itself is stopped
    on context exit, including on SIGINT."""
    # NB: do NOT register a Python LoggingServiceListener. liblinphone fires
    # the log callback from background dispatch workers (e.g. inside DNS
    # resolution); pylinphone's Cython wrapper calls into the Python C-API
    # without holding the GIL, causing SEGVs at PyObject_GetAttrStr. Let
    # liblinphone print to stderr instead.
    linphone.LoggingService.get().set_log_level(linphone.LogLevel.LogLevelMessage)

    factory = linphone.Factory.get()
    core = factory.create_core(rc_path, None, None)

    listener = factory.create_core_listener()
    listener.on_account_registration_state_changed = _on_registration
    listener.on_call_state_changed = _on_call
    listener.on_conference_state_changed = _on_conference
    core.add_listener(listener)
    _LIVE_LISTENERS.append(listener)  # prevent GC of the Python callbacks

    # video_enabled is read-only (derived from capture || display); only the
    # capture/display flags are writable.
    core.video_capture_enabled = True
    core.video_display_enabled = False
    core.mic_enabled = False                # send-only: don't capture mic
    core.echo_cancellation_enabled = False
    core.self_view_enabled = False

    # Media encryption: Linphone's E2EE Group Call (per the official
    # Flexisip-conference docs) requires the *outer* hop-by-hop encryption
    # to be ZRTP, not SDES-SRTP. The server is configured with
    # `encryption=zrtp` on the conference server and rejects SDES-SRTP
    # offers with 488 Not Acceptable. We keep it non-mandatory so the
    # session still works against non-E2EE rooms on the same Core.
    me = linphone.MediaEncryption
    core.media_encryption = getattr(me, "MediaEncryptionZRTP", getattr(me, "ZRTP", None))
    core.set_media_encryption_mandatory(False)

    # RTP bundle (required by the public conference service).
    core.rtp_bundle_enabled = True

    # AVPF (RFC 4585 RTP/SAVPF) is mandatory for sip.linphone.org video
    # conferences. Without it, the answer-side returns "No payload types
    # accepted for video stream" and our tx stays at 0 kbit/s.
    try:
        core.avpf_mode = linphone.AVPFMode.AVPFModeEnabled
    except Exception as exc:  # noqa: BLE001
        log.warning("could not enable AVPF on core: %s", exc)
    # Enough headroom for one HD-ish H.264/H.265 video stream.
    core.upload_bandwidth = 2048   # kbit/s
    core.download_bandwidth = 2048

    # Force a short keyframe (IDR) interval on the local video encoder.
    # MSConferenceModeRouterFullPacket does not forward RTCP PLI/FIR from late
    # joiners back to the sender, so a new participant who joins between
    # keyframes will never see one and the receiver's decoder reports
    # "Resolution 0x0, FPS 0" indefinitely. A 1-second IDR interval bounds the
    # wait, at the cost of ~10–15% extra bitrate.
    cfg = core.config
    cfg.set_int("video", "keyframe_interval", 30)  # frames; ~1s at 30fps
    cfg.set_int("video", "iframe_interval", 30)
    cfg.set_int("video", "vfu_with_iframe_requests", 1)

    # Force IPv4 — Linphone's belle-sip occasionally falls into "no route
    # to host" on dual-stack hosts when the IPv6 path to lime.linphone.org
    # / sip.linphone.org is not actually reachable from the local network.
    core.ipv6_enabled = False

    # LIME X3DH (Group Call E2EE key distribution).
    #
    # NB: liblinphone 5.5.0 kicks off the LIME bootstrap as soon as the Account
    # is added — it tries `lime.linphone.org` even when the account hasn't yet
    # acquired a contact address. On hosts where that endpoint is briefly
    # unreachable (observed here: "No route to host" then SEGV inside the LIME
    # task scheduler), the bootstrap corrupts internal state and crashes.
    #
    # Workaround: when no lime_server_url is provided, leave LIME OFF — the
    # CLI can still join the conference (encryption falls back to plain SRTP
    # without per-sender LIME inner keys). For full Group Call E2EE the user
    # must pass --lime-server explicitly AND have IPv4/IPv6 reachability to
    # that endpoint.
    if lime_server_url:
        core.lime_x3dh_server_url = lime_server_url
        core.lime_x3dh_enabled = True
        log.info("LIME X3DH enabled (server=%s)", lime_server_url)
    else:
        core.lime_x3dh_enabled = False
        log.info("LIME X3DH disabled (no --lime-server provided)")

    core.start()
    log.info("LinphoneCore started (version=%s)", linphone.Core.get_version())

    try:
        yield core
    finally:
        try:
            core.terminate_all_calls()
        except Exception:
            pass
        # Drain pending events so BYE/ACK go out cleanly.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            core.iterate()
            time.sleep(0.02)
        core.stop()
        log.info("LinphoneCore stopped")


def configure_nat_policy(core, *, stun_server: str) -> None:
    """Enable STUN + ICE against the given server (Linphone free service default: stun.linphone.org)."""
    policy = core.nat_policy or core.create_nat_policy()
    policy.stun_server = stun_server
    policy.stun_enabled = True
    policy.ice_enabled = True
    core.nat_policy = policy
    log.info("NAT policy: stun=%s ice=on", stun_server)


def iterate_until_signal(
    core,
    *,
    period: float = 0.02,
    until: float | None = None,
    on_deadline=None,
) -> None:
    """Drive `core.iterate()` until SIGINT/SIGTERM.

    If `until` is given (in seconds, measured from the start of this call) and
    `on_deadline` is a callable, then exactly once when that many seconds have
    elapsed, `on_deadline()` is invoked and the iterate loop continues. This
    is used by `--rotate-after` to fire the EKT-rotation trigger mid-call
    while continuing to drive media."""
    stop = {"q": False}

    def _handler(signum, _frame):
        log.info("signal %d received, shutting down", signum)
        stop["q"] = True

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    start = time.monotonic()
    deadline_done = on_deadline is None or until is None
    last_stats = start
    while not stop["q"]:
        core.iterate()
        time.sleep(period)
        now = time.monotonic()
        if not deadline_done and now - start >= until:
            try:
                on_deadline()
            except Exception as exc:  # noqa: BLE001
                log.error("on_deadline callback raised: %s", exc)
            deadline_done = True
        if now - last_stats >= 5.0:
            _log_call_stats(core)
            last_stats = now


def _log_call_stats(core) -> None:
    call = core.current_call
    if call is None:
        return
    if not hasattr(call, "get_stats"):
        return
    try:
        stats = call.get_stats(linphone.StreamType.StreamTypeVideo)
    except Exception as exc:  # noqa: BLE001
        log.debug("get_stats failed: %s", exc)
        return
    if stats is None:
        return
    try:
        log.info(
            "video stats: tx=%.0f kbit/s rtt=%.0f ms",
            float(stats.upload_bandwidth),
            float(stats.round_trip_delay) * 1000.0,
        )
    except Exception:  # property names drift across SDK versions
        pass


def _on_registration(core, account, state, message):
    name = getattr(state, "name", str(state))
    addr = "?"
    try:
        params = account.params
        if params is not None:
            ia = params.identity_address
            if ia is not None:
                addr = ia.as_string()
    except Exception:  # noqa: BLE001
        pass
    log.info("[registration] %s state=%s msg=%s", addr, name, message)


def _on_call(core, call, state, message):
    name = getattr(state, "name", str(state))
    log.info("[call] state=%s msg=%s", name, message)


def _on_conference(core, conference, state):
    name = getattr(state, "name", str(state))
    log.info("[conference] state=%s", name)


_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "trace": logging.DEBUG,
    "message": logging.INFO,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.CRITICAL,
}


def _forward_log(log_service, domain, level, msg):
    name = getattr(level, "name", str(level)).lower()
    py_level = _LEVEL_MAP.get(name, logging.INFO)
    log.log(py_level, "linphone[%s]: %s", domain, msg)
