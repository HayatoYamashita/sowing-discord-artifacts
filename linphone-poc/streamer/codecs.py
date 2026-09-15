from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def configure_video_codecs(core, enabled_mimes: tuple[str, ...]) -> list[str]:
    """Enable the requested video codecs; disable the others.

    `enabled_mimes` lists *additional* codecs we want on. VP8 is forcibly
    kept enabled regardless, because the sip.linphone.org Group Call SFU
    only relays video when VP8 is offered (without it the answer carries
    no acceptable payload types and our tx stays at 0)."""
    wanted = {m.upper() for m in enabled_mimes} | {"VP8"}
    enabled: list[str] = []

    for pt in list(core.video_payload_types):
        mime = (pt.mime_type or "").upper()
        keep = mime in wanted
        try:
            pt.enable(keep) if hasattr(pt, "enable") else _toggle(pt, keep)
        except Exception as exc:
            log.warning("could not toggle payload %s: %s", mime, exc)
            continue
        if keep:
            enabled.append(mime)
            log.info("payload enabled: %s (clock=%d)", mime, getattr(pt, "clock_rate", 0))
        else:
            log.debug("payload disabled: %s", mime)

    if not enabled:
        raise RuntimeError(
            f"none of {enabled_mimes} were found among available video payload types"
        )
    return enabled


def _toggle(pt, enabled: bool) -> None:
    # Some bindings expose this as a settable property instead of a method.
    pt.enabled = enabled  # type: ignore[attr-defined]
