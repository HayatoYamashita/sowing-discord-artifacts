from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

PLUGIN_WEBCAM_NAME = "MovieCam"  # must match MSWebCamDesc.driver_type in msmoviecam.c


def export_plugin_env(*, video_file: str, width: int, height: int, fps: float) -> None:
    """Populate the env vars consumed by libmsmoviecam at filter preprocess.

    Must be called BEFORE creating the LinphoneCore: the plugin reads its
    environment when the MSFilter is constructed by mediastreamer2."""
    os.environ["MSMOVIECAM_VIDEO"] = video_file
    os.environ["MSMOVIECAM_W"] = str(width)
    os.environ["MSMOVIECAM_H"] = str(height)
    os.environ["MSMOVIECAM_FPS"] = f"{fps:g}"
    log.info(
        "msmoviecam env: video=%s size=%dx%d fps=%g",
        video_file, width, height, fps,
    )


def set_plugin_dir(ms_plugin_dir: str, lib_plugin_dir: str | None = None) -> None:
    """Point liblinphone's plugin lookup at our directories BEFORE Core creation.

    Two distinct paths must be set:

    * `msplugins_dir` — where mediastreamer2 looks for `libms*.so` plugins
      (this is where our `libmsmoviecam.so` lives).

    * `liblinphone_plugins_dir` — where liblinphone-level plugins live.
      The EKT server plugin (`liblinphone_ektserver.so`) lives here when
      built with `-DENABLE_EKT_SERVER_PLUGIN=ON`. On macOS it's installed
      INSIDE the linphone.framework bundle
      (`linphone.framework/Versions/A/Libraries/`), which is a different
      directory from the mediastreamer2 plugins.

      This MUST be non-empty even when no liblinphone plugin is present:
      `Core::initPlugins()` otherwise falls back to
      `MacPlatformHelpers::getPluginsDir()`, which in SDK 5.5.0 crashes with
      EXC_BAD_ACCESS — it assigns the NULL return of `CFStringGetCStringPtr`
      to a `std::string` (mac-platform-helpers.mm:139). If only `ms_plugin_dir`
      is given, it is used for both (legacy behaviour for the streamer CLI,
      which doesn't need EKT)."""
    import linphone

    factory = linphone.Factory.get()
    factory.msplugins_dir = ms_plugin_dir
    factory.liblinphone_plugins_dir = lib_plugin_dir or ms_plugin_dir
    log.info("linphone msplugins_dir = %s", ms_plugin_dir)
    log.info("linphone liblinphone_plugins_dir = %s", lib_plugin_dir or ms_plugin_dir)


def select_moviecam_device(core) -> str:
    """Pick the MovieCam webcam registered by the msmoviecam plugin."""
    devices = list(core.video_devices_list)
    if not devices:
        raise RuntimeError("no video capture devices available")

    log.info("available video devices (%d):", len(devices))
    for d in devices:
        log.info("  - %s", d)

    matches = [d for d in devices if "moviecam" in d.lower()]
    if not matches:
        raise RuntimeError(
            "MovieCam device not found. Was libmsmoviecam.dylib loaded? "
            "Check that POC_LINPHONE_PLUGIN_DIR / Factory.msplugins_dir was set "
            "BEFORE Core creation."
        )
    chosen = matches[0]
    core.video_device = chosen
    log.info("selected video device: %s", chosen)
    return chosen
