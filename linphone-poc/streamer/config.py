from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

CodecChoice = Literal["h264", "h265", "both"]

# Linphone free service defaults (mirrors linphone-android
# `app/src/main/assets/assistant_linphone_default_values`).
LINPHONE_SIP_DOMAIN = "sip.linphone.org"
LINPHONE_PROXY = "sip:sip.linphone.org;transport=tls"
LINPHONE_AV_CONFERENCE_FACTORY = "sip:videoconference-factory@sip.linphone.org"
LINPHONE_LIME_SERVER = "https://lime.linphone.org/lime-server/lime-server.php"
LINPHONE_STUN_SERVER = "stun.linphone.org"


@dataclass(frozen=True)
class StreamerConfig:
    sip_uri: str
    sip_password: str
    conference_uri: str
    video_file: str

    proxy: str = LINPHONE_PROXY
    conference_factory_uri: str = LINPHONE_AV_CONFERENCE_FACTORY
    # LIME is opt-in (see streamer/core.py for the rationale): keeping it on by
    # default crashed when lime.linphone.org wasn't reachable at REGISTER time.
    lime_server: str | None = None
    stun_server: str = LINPHONE_STUN_SERVER

    width: int = 640
    height: int = 480
    fps: float = 30.0

    codec: CodecChoice = "both"
    plugin_dir: str | None = None  # filled from POC_LINPHONE_PLUGIN_DIR if not given
    rc_path: str | None = None
    log_level: str = "INFO"

    enabled_codec_mimes: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        if self.codec == "h264":
            mimes = ("H264",)
        elif self.codec == "h265":
            mimes = ("H265",)
        else:
            mimes = ("H265", "H264")
        object.__setattr__(self, "enabled_codec_mimes", mimes)

        if self.plugin_dir is None:
            env_dir = os.environ.get("POC_LINPHONE_PLUGIN_DIR")
            if env_dir:
                object.__setattr__(self, "plugin_dir", env_dir)

        if not self.video_file or not os.path.isfile(self.video_file):
            raise FileNotFoundError(f"--video-file not found: {self.video_file!r}")
        if self.plugin_dir is None:
            raise RuntimeError(
                "plugin directory unknown: pass --plugin-dir or "
                "set POC_LINPHONE_PLUGIN_DIR (see build/envrc)"
            )
