from __future__ import annotations

import argparse
import logging
import os
import stat
import sys
from pathlib import Path

from streamer.config import (
    LINPHONE_AV_CONFERENCE_FACTORY,
    LINPHONE_LIME_SERVER,
    LINPHONE_PROXY,
    LINPHONE_STUN_SERVER,
    StreamerConfig,
)

DEFAULT_SIP_PASSWORD_FILE = ".sip-password"
SIP_PASSWORD_ENV = "STREAMER_SIP_PASSWORD"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="streamer",
        description=(
            "Send-only Linphone CLI that joins a Group-Call E2EE conference "
            "and streams an mp4/mov file in a loop via the msmoviecam plugin. "
            "Defaults target the Linphone free service (sip.linphone.org)."
        ),
    )
    p.add_argument("--video-file", required=True, help="path to .mp4 / .mov / any ffmpeg-readable file")
    p.add_argument("--sip-uri", required=True, help="e.g. sip:<sender-user>@sip.linphone.org")
    p.add_argument("--sip-password", default=None,
                   help=f"SIP password. If omitted, falls back to --sip-password-file, "
                        f"then ${SIP_PASSWORD_ENV}, then ./{DEFAULT_SIP_PASSWORD_FILE}.")
    p.add_argument("--sip-password-file", default=None,
                   help=f"path to a file whose contents are the SIP password "
                        f"(default: ./{DEFAULT_SIP_PASSWORD_FILE} if it exists)")
    p.add_argument("--conference-uri", default=None,
                   help="join: invite into this existing conference URI "
                        "(focus URI / room URI). Required in join mode, "
                        "ignored in create mode.")
    p.add_argument("--create", action="store_true",
                   help="organizer mode: create a new conference at the "
                        "factory URI (with security_level=e2ee by default) "
                        "and invite participants. The conference URI is "
                        "announced in logs once Created.")
    p.add_argument("--invite", action="append", default=[], metavar="SIP_URI",
                   help="participant SIP URI to invite (only with --create; "
                        "repeatable). Example: --invite sip:receiver@example.org")
    p.add_argument("--security-level", choices=("none", "ptp", "e2ee"), default="e2ee",
                   help="ConferenceParams.security_level when creating "
                        "(default: e2ee). Ignored in join mode.")
    p.add_argument("--subject", default="poc-linphone",
                   help="conference subject when creating (default: poc-linphone)")
    p.add_argument("--rotate-after", type=float, default=None, metavar="SEC",
                   help="(Step-2 PoC) after the streamer has been running for SEC "
                        "seconds, invite a dummy SIP URI as a new participant. "
                        "On the focus this fires "
                        "Conference::notifyAllowedParticipantListChanged → the EKT "
                        "plugin regenerates the conference master key and "
                        "re-distributes it via NOTIFY. Combined with the focus's "
                        "EKT_NOTIFY_BLOCKLIST env-var hook, this realises "
                        "paper §5.1 Phase-1 (key-state divergence). Default: "
                        "do not trigger rotation.")
    p.add_argument("--rotate-uri",
                   default="sip:_poc_attack_dummy_DO_NOT_CALL@invalid",
                   metavar="SIP_URI",
                   help="(Step-2 PoC) the dummy SIP URI to invite at rotation "
                        "time. Must be a URI the conference has not previously "
                        "seen in its allowed-list. The REFER will fail at the "
                        "SIP layer (the focus's rotation side-effect persists "
                        "regardless). The default uses the RFC 6761 reserved "
                        "TLD `invalid` so the URI cannot be registered by any "
                        "real Linphone user and the request is unroutable.")
    p.add_argument("--rotate-arm-file", default=None, metavar="PATH",
                   help="(Step-2 PoC) path to a sentinel file that the focus's "
                        "EKT_NOTIFY_BLOCKLIST_ARM_FILE env-var watches. When "
                        "given, the streamer creates this file immediately "
                        "before sending the rotation REFER. This makes the "
                        "blocklist take effect only at rotation time, so the "
                        "initial EKT distribution to all participants is "
                        "unaffected and only the rotation's new key gets "
                        "withheld from the blocklisted devices (= paper §5.1 "
                        "Phase 1 exactly). The focus must be started with the "
                        "same path in EKT_NOTIFY_BLOCKLIST_ARM_FILE.")
    p.add_argument("--proxy", default=LINPHONE_PROXY,
                   help=f"SIP server address (default: {LINPHONE_PROXY})")
    p.add_argument("--conference-factory-uri", default=LINPHONE_AV_CONFERENCE_FACTORY,
                   help=f"audio/video conference factory URI (default: {LINPHONE_AV_CONFERENCE_FACTORY})")
    p.add_argument("--conference-factory-uri-file", default=None,
                   help="read --conference-factory-uri from this file (one URI "
                        "per line, leading/trailing whitespace stripped). "
                        "Set by python -m streamer.focus to its GRUU URI "
                        "(default: build/focus.uri) — use this instead of "
                        "--conference-factory-uri to bypass SIP forking when "
                        "the focus's identity is also registered to mobile "
                        "devices.")
    p.add_argument("--lime-server", default=None,
                   help=f"LIME/X3DH server URL. Opt-in (default: disabled). "
                        f"For Linphone's public service pass: {LINPHONE_LIME_SERVER}. "
                        f"Required for Group-Call inner E2EE per-sender keys.")
    p.add_argument("--stun-server", default=LINPHONE_STUN_SERVER,
                   help=f"STUN server (default: {LINPHONE_STUN_SERVER})")
    p.add_argument("--width", type=int, default=640)
    p.add_argument("--height", type=int, default=480)
    p.add_argument("--fps", type=float, default=30.0)
    p.add_argument("--codec", choices=("h264", "h265", "both"), default="both")
    p.add_argument("--plugin-dir", default=None,
                   help="directory containing libmsmoviecam.so "
                        "(defaults to $POC_LINPHONE_PLUGIN_DIR)")
    p.add_argument("--lib-plugin-dir", default=None,
                   help="directory containing liblinphone_* plugins (only used "
                        "by the focus daemon for EKT; defaults to "
                        "$POC_LINPHONE_LIB_PLUGIN_DIR, then --plugin-dir)")
    p.add_argument("--rc-path", default=None, help="optional linphonerc factory config path")
    p.add_argument("--log-level", default="INFO")
    return p


def _resolve_sip_password(args) -> str:
    """Resolve the SIP password from (in priority order):
      1) --sip-password
      2) --sip-password-file
      3) $STREAMER_SIP_PASSWORD
      4) ./.sip-password (if it exists)
    Raises SystemExit if none of those yield a non-empty value."""
    log = logging.getLogger("streamer.password")

    if args.sip_password:
        return args.sip_password

    path: Path | None = None
    if args.sip_password_file:
        path = Path(args.sip_password_file).expanduser()
        if not path.is_file():
            raise SystemExit(f"--sip-password-file not found: {path}")
    else:
        env = os.environ.get(SIP_PASSWORD_ENV)
        if env:
            log.info("using SIP password from $%s", SIP_PASSWORD_ENV)
            return env
        default = Path(DEFAULT_SIP_PASSWORD_FILE)
        if default.is_file():
            path = default

    if path is None:
        raise SystemExit(
            "no SIP password provided. Pass one of:\n"
            "  --sip-password '<value>'\n"
            f"  --sip-password-file <path>      (a file whose contents are the password)\n"
            f"  ${SIP_PASSWORD_ENV}=<value>     (environment variable)\n"
            f"  ./{DEFAULT_SIP_PASSWORD_FILE}   (default hidden file in cwd, gitignored)"
        )

    # World-readable warning (best-effort; non-fatal).
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            log.warning("%s is group/world-readable (mode 0o%o); consider `chmod 600`.",
                        path, mode & 0o777)
    except OSError:
        pass

    pw = path.read_text().rstrip("\r\n")
    if not pw:
        raise SystemExit(f"SIP password file is empty: {path}")
    log.info("using SIP password from %s", path)
    return pw


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s %(name)s | %(message)s",
    )

    if not args.create and not args.conference_uri:
        raise SystemExit("either --conference-uri (join mode) or --create (organizer mode) is required")

    sip_password = _resolve_sip_password(args)

    if args.conference_factory_uri_file:
        try:
            args.conference_factory_uri = Path(
                args.conference_factory_uri_file
            ).read_text().strip().splitlines()[0].strip()
        except (OSError, IndexError) as exc:
            raise SystemExit(
                f"--conference-factory-uri-file {args.conference_factory_uri_file}: "
                f"{exc}"
            )
        logging.getLogger("streamer").info(
            "conference factory URI loaded from %s: %s",
            args.conference_factory_uri_file, args.conference_factory_uri,
        )

    cfg = StreamerConfig(
        sip_uri=args.sip_uri,
        sip_password=sip_password,
        conference_uri=args.conference_uri or "(pending — create mode)",
        video_file=args.video_file,
        proxy=args.proxy,
        conference_factory_uri=args.conference_factory_uri,
        lime_server=args.lime_server,
        stun_server=args.stun_server,
        width=args.width,
        height=args.height,
        fps=args.fps,
        codec=args.codec,
        plugin_dir=args.plugin_dir,
        rc_path=args.rc_path,
        log_level=args.log_level,
    )

    # Set the plugin's env vars BEFORE we import linphone / create Core.
    from streamer.camera import (
        export_plugin_env,
        select_moviecam_device,
        set_plugin_dir,
    )
    export_plugin_env(
        video_file=cfg.video_file,
        width=cfg.width,
        height=cfg.height,
        fps=cfg.fps,
    )
    # Importing linphone is heavy; defer until env is ready.
    from streamer.account import register_account
    from streamer.codecs import configure_video_codecs
    from streamer.conference import (
        create_e2ee_conference,
        join_e2ee_conference,
        trigger_rotation,
    )
    from streamer.core import configure_nat_policy, iterate_until_signal, linphone_core

    set_plugin_dir(cfg.plugin_dir, args.lib_plugin_dir or os.environ.get("POC_LINPHONE_LIB_PLUGIN_DIR"))  # type: ignore[arg-type]

    log = logging.getLogger("streamer")
    log.info("config: video=%s sip=%s conf=%s codec=%s",
             cfg.video_file, cfg.sip_uri, cfg.conference_uri, cfg.codec)

    with linphone_core(rc_path=cfg.rc_path, lime_server_url=cfg.lime_server) as core:
        configure_nat_policy(core, stun_server=cfg.stun_server)
        select_moviecam_device(core)
        configure_video_codecs(core, cfg.enabled_codec_mimes)

        register_account(
            core,
            sip_uri=cfg.sip_uri,
            password=cfg.sip_password,
            proxy=cfg.proxy,
            conference_factory_uri=cfg.conference_factory_uri,
            lime_server=cfg.lime_server,
        )
        conf = None
        if args.create:
            conf = create_e2ee_conference(
                core,
                subject=args.subject,
                participants=args.invite,
                security=args.security_level,
            )
        else:
            join_e2ee_conference(core, conference_uri=args.conference_uri)

        log.info("streaming %s on loop — press Ctrl-C to stop", cfg.video_file)

        if args.rotate_after is not None:
            if conf is None:
                log.warning("--rotate-after ignored: rotation trigger requires "
                            "--create (organizer mode); join mode does not own "
                            "the conference object")
                iterate_until_signal(core)
            else:
                log.info("rotation trigger armed: will invite %s in %.1f s",
                         args.rotate_uri, args.rotate_after)
                iterate_until_signal(
                    core,
                    until=args.rotate_after,
                    on_deadline=lambda: trigger_rotation(
                        core, conf, args.rotate_uri,
                        arm_file=args.rotate_arm_file,
                    ),
                )
        else:
            iterate_until_signal(core)

    return 0


if __name__ == "__main__":
    sys.exit(main())
