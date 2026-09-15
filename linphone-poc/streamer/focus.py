"""Self-hosted Linphone Group-Call E2EE focus daemon.

Background
----------
The public sip.linphone.org SFU refuses to host
LinphoneConferenceSecurityLevelEndToEnd conferences with `488 Not Acceptable`:
that response is emitted by
`liblinphone/src/conference/server-conference.cpp:checkServerConfiguration`
when (a) the focus's audio/video `conference_mode` is not
`MSConferenceModeRouterFullPacket`, or (b) the EKT server plugin is not
loaded. Both checks are server-side; the client (our streamer/) is already
fully wired for E2EE.

What this daemon does
---------------------
Rather than running a full `flexisip-conference` deployment, we run a tiny
liblinphone Core configured in *conference server* mode
(`linphone_core_enable_conference_server`), which is the same API the SDK's
own tester uses (`Focus` class in
`liblinphone/tester/local-conference-tester-functions.h`). On macOS the EKT
plugin (`liblinphone_ektserver.so`) is loaded automatically when found in
`liblinphone_plugins_dir`.

The daemon registers as a regular SIP user (e.g.
`sip:<focus-user>@sip.linphone.org`) and sets its own identity as the
account's `conference_factory_address`, so clients that point
`--conference-factory-uri` at this user's URI are routed by the upstream
SIP proxy directly to us; we then host the E2EE conference locally.
Media flows participant ↔ focus (not through sip.linphone.org).
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from contextlib import contextmanager

from streamer.cli import (
    DEFAULT_SIP_PASSWORD_FILE,
    SIP_PASSWORD_ENV,
    _resolve_sip_password,
)
from streamer.config import LINPHONE_PROXY, LINPHONE_STUN_SERVER

log = logging.getLogger("streamer.focus")

# MSConferenceMode values, mediastreamer2/include/mediastreamer2/msconference.h:
#   MSConferenceModeMixer            = 0
#   MSConferenceModeRouterPayload    = 1
#   MSConferenceModeRouterFullPacket = 2
MS_CONFERENCE_MODE_ROUTER_FULL_PACKET = 2

_LIVE_LISTENERS: list = []


@contextmanager
def focus_core(*, rc_path: str | None = None,
               codec_mimes: tuple[str, ...] = ("H264",)):
    """Bring up a LinphoneCore configured as an E2EE-capable focus server.

    Mirrors `Focus::configureFocus()` in
    liblinphone/tester/local-conference-tester-functions.h and
    `configure_end_to_end_encrypted_conference_server()` in
    liblinphone/tester/local-conference-tester-functions.cpp."""
    import linphone

    linphone.LoggingService.get().set_log_level(linphone.LogLevel.LogLevelMessage)

    factory = linphone.Factory.get()
    core = factory.create_core(rc_path, None, None)

    listener = factory.create_core_listener()
    listener.on_account_registration_state_changed = _on_registration
    listener.on_conference_state_changed = _on_conference
    listener.on_subscription_state_changed = _on_subscription
    listener.on_publish_state_changed = _on_publish
    core.add_listener(listener)
    _LIVE_LISTENERS.append(listener)

    # Routing semantics: MSConferenceModeRouterFullPacket forwards SRTP packets
    # verbatim, so the focus never decodes/encodes media. BUT the focus's
    # conference-side MediaSession still needs to think of itself as a fully
    # bidirectional video participant — otherwise its outgoing SDP to other
    # participants tags the relayed video stream as `a=inactive` and the
    # MSPacketRouter is never linked between sender's MSRtpRecv and receiver A's
    # MSRtpSend (observed symptom: 0 packets > 500 bytes flowing focus→receiver A,
    # only audio bundle gets routed).
    #
    # The tester's Focus::configureFocus() does NOT touch
    # video_capture/display, leaving both at their defaults (True). We mirror
    # that, AND pin the capture device to a non-camera source ("Static picture")
    # so no AVFoundation permission prompt fires and no camera is actually
    # opened — but the video stream stays "active" for SDP/routing purposes.
    core.video_capture_enabled = True
    core.video_display_enabled = True
    core.mic_enabled = False
    core.echo_cancellation_enabled = False
    core.self_view_enabled = False
    # Pin capture to the Static picture pseudo-device. mediastreamer2 registers
    # it unconditionally (we saw it at startup: "Webcam StaticImage: Static
    # picture added"), it serves a fixed image without opening any hardware.
    for dev in list(core.video_devices_list):
        if "staticimage" in dev.lower() or "static picture" in dev.lower():
            core.video_device = dev
            log.info("focus video device pinned to %s", dev)
            break
    # Suppress any actual rendering output.
    if hasattr(core, "video_display_filter"):
        try:
            core.video_display_filter = "MSVoidDisplay"
        except Exception:  # noqa: BLE001
            pass

    # E2EE outer hop encryption MUST be ZRTP — both clients and focus need to
    # advertise it on SDP, and the Belledonne wiki's conference-server config
    # also pins `encryption=zrtp`. SDES-SRTP would be silently downgraded.
    me = linphone.MediaEncryption
    core.media_encryption = getattr(me, "MediaEncryptionZRTP", getattr(me, "ZRTP", None))
    core.set_media_encryption_mandatory(False)

    core.rtp_bundle_enabled = True
    core.ipv6_enabled = False

    core.lime_x3dh_enabled = False  # focus does not own a LIME identity

    # *** The two server-side knobs that, when missing, trigger the 488 from
    # server-conference.cpp:checkServerConfiguration. ***
    cfg = core.config
    cfg.set_int("sound", "conference_mode", MS_CONFERENCE_MODE_ROUTER_FULL_PACKET)
    cfg.set_int("video", "conference_mode", MS_CONFERENCE_MODE_ROUTER_FULL_PACKET)
    # Match the Focus tester harness: don't gate conference creation on a
    # scheduled start window — accept INVITEs immediately.
    cfg.set_int("misc", "conference_availability_before_start", 0)
    cfg.set_int("misc", "conference_expire_period", 0)
    cfg.set_int("misc", "hide_empty_chat_rooms", 0)
    cfg.set_int("misc", "hide_chat_rooms_from_removed_proxies", 0)
    cfg.set_int("sip", "reject_duplicated_calls", 0)

    # Tell liblinphone this Core is a focus, not a regular client. This makes
    # incoming INVITEs to the conference-factory URI hit
    # ServerConference::checkServerConfiguration (which is the very check we
    # are arranging to pass).
    core.conference_server_enabled = True

    core.start()
    log.info("focus LinphoneCore started (version=%s, conference_server=True)",
             linphone.Core.get_version())

    # Pin the focus's video codec list to H.264 only. The focus's outgoing SDP
    # offer (focus → participant) lists payload types in this order, and the
    # participant typically picks the first compatible one. With H.264 and
    # H.265 both offered, Linphone Android 6.2.0 picked H.265 — but H.265
    # bitstreams in transfer-mode conferences require VPS/SPS/PPS to arrive
    # before any decode, and the receiver missed them when it joined
    # mid-stream (no PLI/FIR forwarding in MSConferenceModeRouterFullPacket).
    # H.264 is more forgiving in this scenario.
    from streamer.codecs import configure_video_codecs
    try:
        configure_video_codecs(core, codec_mimes)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not narrow focus codec list to %s: %s",
                    codec_mimes, exc)

    # The EKT plugin's init routine calls core.set_ekt_plugin_loaded(true)
    # (see ekt-server/src/ektserver.cpp:55). Read it back to confirm load.
    if not core.is_ekt_plugin_loaded:
        log.warning(
            "EKT server plugin did NOT load — the focus will still reject "
            "E2EE conferences with 488. Re-run the SDK build with "
            "-DENABLE_EKT_SERVER_PLUGIN=ON and verify liblinphone_ektserver.so "
            "is present in liblinphone_plugins_dir."
        )
    else:
        log.info("EKT server plugin loaded (liblinphone_ektserver_init fired)")

    try:
        yield core
    finally:
        try:
            core.terminate_all_calls()
        except Exception:
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            core.iterate()
            time.sleep(0.02)
        core.stop()
        log.info("focus LinphoneCore stopped")


def configure_focus_account(
    core,
    *,
    sip_uri: str,
    password: str,
    proxy: str,
    timeout: float = 30.0,
):
    """Register the focus's SIP account and pin its identity as the
    conference-factory address.

    The pin is the key bit: when this account is `core.default_account`,
    incoming INVITEs to its identity URI are matched as conference-factory
    INVITEs (instead of as a regular point-to-point call), triggering the
    server-conference path."""
    import linphone

    identity = core.interpret_url(sip_uri, True)
    if identity is None:
        raise ValueError(f"could not parse SIP URI: {sip_uri}")
    domain = identity.domain
    user = identity.username

    server_addr = core.interpret_url(proxy, True)
    if server_addr is None:
        raise ValueError(f"could not parse proxy URI: {proxy}")

    params = core.create_account_params()
    params.identity_address = identity
    params.server_address = server_addr
    params.register_enabled = True
    params.realm = domain
    params.rtp_bundle_enabled = True

    # *** the focus IS the factory: it advertises its own identity as the
    # conference-factory address. Mirrors Focus::configureFocus() in
    # local-conference-tester-functions.h:239-241. ***
    if hasattr(params, "audio_video_conference_factory_address"):
        params.audio_video_conference_factory_address = identity
    elif hasattr(params, "conference_factory_address"):
        params.conference_factory_address = identity
    else:
        params.conference_factory_uri = sip_uri

    try:
        params.avpf_mode = linphone.AVPFMode.AVPFModeEnabled
    except Exception as exc:  # noqa: BLE001
        log.debug("could not set AVPF mode: %s", exc)

    account = core.create_account(params)
    core.add_account(account)
    core.default_account = account

    # sip.linphone.org's Flexisip rejects E2EE INVITEs to contacts that do not
    # advertise "lime" in +org.linphone.specs:
    #   `488 Not acceptable here`
    #   `Warning: 399 sip.linphone.org "Lime (end to end encryption) is required
    #    to use this service"`.
    # The focus does not own a LIME identity (it never decrypts in
    # MSConferenceModeRouterFullPacket), but the Contact MUST carry the feature
    # tag so Flexisip's E2EE-policy check passes.
    #
    # Setting the full spec list AFTER add_account is necessary because
    # Account::onAudioVideoConferenceFactoryAddressChanged() fires during
    # add_account and only adds "conference/2.0" to the spec map — it does not
    # add lime/groupchat/ephemeral. We mirror what Linphone iOS/Android send
    # (`conference/2.0,groupchat/1.2,ephemeral/1.1,lime`).
    core.linphone_specs_list = [
        "conference/2.0",
        "groupchat/1.2",
        "ephemeral/1.1",
        "lime",
    ]
    log.info("focus spec list set: %s",
             ",".join(list(core.linphone_specs_list)))

    auth = linphone.Factory.get().create_auth_info(user, None, domain)
    auth.password = password
    auth.username = user
    auth.domain = domain
    auth.realm = domain
    core.add_auth_info(auth)

    OK = linphone.RegistrationState.RegistrationStateOk
    FAILED = linphone.RegistrationState.RegistrationStateFailed

    log.info("registering focus %s via %s (conference factory = own identity)",
             sip_uri, proxy)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        core.iterate()
        st = account.state
        if st == OK:
            log.info("focus account registered (state=Ok)")
            return account
        if st == FAILED:
            raise RuntimeError(f"focus registration failed (state={st!r})")
        time.sleep(0.05)
    raise TimeoutError(f"focus registration timed out (last state={account.state!r})")


def configure_nat_policy(core, *, stun_server: str) -> None:
    policy = core.nat_policy or core.create_nat_policy()
    policy.stun_server = stun_server
    policy.stun_enabled = True
    policy.ice_enabled = True
    core.nat_policy = policy
    log.info("focus NAT policy: stun=%s ice=on", stun_server)


def iterate_until_signal(core, *, period: float = 0.02) -> None:
    stop = {"q": False}

    def _handler(signum, _frame):
        log.info("signal %d received, shutting down focus", signum)
        stop["q"] = True

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    while not stop["q"]:
        core.iterate()
        time.sleep(period)


def _on_registration(core, account, state, message):
    name = getattr(state, "name", str(state))
    log.info("[focus registration] state=%s msg=%s", name, message)


def _on_conference(core, conference, state):
    name = getattr(state, "name", str(state))
    addr = "?"
    try:
        a = conference.conference_address
        if a is not None:
            addr = a.as_string()
    except Exception:
        pass
    log.info("[focus conference] state=%s addr=%s", name, addr)


def _on_subscription(core, ev, state):
    name = getattr(state, "name", str(state))
    log.info("[focus subscribe] state=%s event=%s", name,
             getattr(ev, "name", "?"))


def _on_publish(core, ev, state):
    name = getattr(state, "name", str(state))
    log.info("[focus publish] state=%s event=%s", name,
             getattr(ev, "name", "?"))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m streamer.focus",
        description=(
            "Self-hosted Linphone Group-Call E2EE focus daemon. "
            "Registers as a SIP user and accepts E2EE conference INVITEs. "
            "Required because sip.linphone.org's public SFU does not load the "
            "EKT server plugin (488 Not Acceptable)."
        ),
    )
    p.add_argument("--sip-uri", required=True,
                   help="focus SIP URI (e.g. sip:<focus-user>@sip.linphone.org)")
    p.add_argument("--sip-password", default=None,
                   help=f"SIP password. If omitted, falls back to "
                        f"--sip-password-file, then ${SIP_PASSWORD_ENV}, "
                        f"then ./{DEFAULT_SIP_PASSWORD_FILE}.")
    p.add_argument("--sip-password-file", default=None,
                   help=f"path to a file whose contents are the SIP password "
                        f"(default: ./{DEFAULT_SIP_PASSWORD_FILE} if it exists)")
    p.add_argument("--proxy", default=LINPHONE_PROXY,
                   help=f"SIP server (default: {LINPHONE_PROXY})")
    p.add_argument("--stun-server", default=LINPHONE_STUN_SERVER,
                   help=f"STUN server (default: {LINPHONE_STUN_SERVER})")
    p.add_argument("--lib-plugin-dir", default=None,
                   help="directory containing liblinphone_ektserver.so "
                        "(default: $POC_LINPHONE_LIB_PLUGIN_DIR)")
    p.add_argument("--ms-plugin-dir", default=None,
                   help="directory containing libms*.so plugins (unused by the "
                        "focus itself, but liblinphone refuses to start without "
                        "msplugins_dir set; default: $POC_LINPHONE_PLUGIN_DIR)")
    p.add_argument("--codec", choices=("h264", "h265", "both"), default="h264",
                   help="video codec(s) the focus advertises to participants "
                        "(default: h264). Must match the sender's --codec "
                        "choice — the focus relays SRTP packets verbatim, so a "
                        "codec mismatch leaves receivers with a confused "
                        "decoder. h265 requires receivers that support mid-"
                        "stream H.265 join with frequent IDRs.")
    p.add_argument("--rc-path", default=None,
                   help="optional linphonerc factory config path")
    p.add_argument("--log-level", default="INFO")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s %(name)s | %(message)s",
    )

    sip_password = _resolve_sip_password(args)

    lib_plugin_dir = args.lib_plugin_dir or os.environ.get("POC_LINPHONE_LIB_PLUGIN_DIR")
    ms_plugin_dir = args.ms_plugin_dir or os.environ.get("POC_LINPHONE_PLUGIN_DIR")
    if not lib_plugin_dir:
        raise SystemExit(
            "liblinphone plugin dir unknown — pass --lib-plugin-dir or source "
            "build/envrc (sets POC_LINPHONE_LIB_PLUGIN_DIR). Without it the "
            "EKT server plugin won't load and INVITE will still be rejected "
            "with 488."
        )
    if not ms_plugin_dir:
        ms_plugin_dir = lib_plugin_dir  # any non-empty path satisfies init

    from streamer.camera import set_plugin_dir
    set_plugin_dir(ms_plugin_dir, lib_plugin_dir)

    log.info("focus dirs: ms=%s lib=%s", ms_plugin_dir, lib_plugin_dir)

    if args.codec == "h264":
        codec_mimes = ("H264",)
    elif args.codec == "h265":
        codec_mimes = ("H265",)
    else:
        codec_mimes = ("H264", "H265")

    with focus_core(rc_path=args.rc_path, codec_mimes=codec_mimes) as core:
        configure_nat_policy(core, stun_server=args.stun_server)
        configure_focus_account(
            core,
            sip_uri=args.sip_uri,
            password=sip_password,
            proxy=args.proxy,
        )
        # *** SIP-fork mitigation ***
        # The free Linphone service stores every device's contact in Flexisip
        # (including push-only mobile contacts that *don't expire on logout*),
        # so an INVITE to `sip:<focus-user>@sip.linphone.org` is *forked* to all of
        # them. The proxy then sits on our focus's 302 for ~32s waiting for
        # the (now-uninstallable) push targets to time out. To bypass forking
        # entirely, clients must INVITE the focus's *GRUU* (`;gr=urn:uuid:…`),
        # which routes to exactly one Flexisip contact. We expose the focus's
        # full GRUU URI in a file so the CLI can pick it up with
        # `--conference-factory-uri-file <path>`.
        account = core.default_account
        contact = account.contact_address if account else None
        focus_uri = contact.as_string() if contact is not None else args.sip_uri
        # contact.as_string() wraps with <…>; the rest of liblinphone accepts
        # bare sip: URIs without angle brackets. Strip them, and trim
        # belle-sip transport params back down to identity + ;gr=… so the
        # INVITE Request-URI matches a single Flexisip contact (one fork).
        focus_uri = focus_uri.strip("<>")
        import re
        m = re.match(r"sip:([^@]+)@([^;:>]+).*?(;gr=urn:uuid:[0-9a-fA-F-]+)",
                     focus_uri)
        if m:
            focus_uri = f"sip:{m.group(1)}@{m.group(2)}{m.group(3)}"
        from pathlib import Path
        uri_file = Path("build") / "focus.uri"
        try:
            uri_file.parent.mkdir(exist_ok=True)
            uri_file.write_text(focus_uri + "\n")
            log.info("wrote focus URI to %s : %s", uri_file, focus_uri)
        except OSError as exc:
            log.warning("could not write focus URI file %s: %s", uri_file, exc)
        log.info(
            "focus is ready. Tell streaming clients to use "
            "--conference-factory-uri %s "
            "(or --conference-factory-uri-file %s) and --security-level e2ee. "
            "Ctrl-C to shut down.", focus_uri, uri_file,
        )
        iterate_until_signal(core)

    return 0


if __name__ == "__main__":
    sys.exit(main())
