from __future__ import annotations

import logging
import time

import linphone  # noqa: F401  (provided by the built pylinphone module)

log = logging.getLogger(__name__)


def register_account(
    core,
    *,
    sip_uri: str,
    password: str,
    proxy: str | None,
    conference_factory_uri: str | None,
    lime_server: str | None,
    timeout: float = 30.0,
) -> "linphone.Account":
    """Create + register a SIP Account using the modern Account API.

    Blocks (iterating Core) until registration is `Ok` or `timeout` elapses."""
    identity = core.interpret_url(sip_uri, True)
    if identity is None:
        raise ValueError(f"could not parse SIP URI: {sip_uri}")
    domain = identity.domain

    server_uri = proxy or f"sip:{domain};transport=tls"
    server_addr = core.interpret_url(server_uri, True)
    if server_addr is None:
        raise ValueError(f"could not parse proxy/server URI: {server_uri}")

    params = core.create_account_params()
    params.identity_address = identity
    params.server_address = server_addr
    params.register_enabled = True
    params.realm = domain
    params.rtp_bundle_enabled = True
    try:
        # AVPFMode enum members are prefixed (e.g. AVPFModeEnabled).
        params.avpf_mode = linphone.AVPFMode.AVPFModeEnabled
    except Exception as exc:  # noqa: BLE001
        log.debug("could not set AVPF mode: %s", exc)

    if conference_factory_uri:
        # Prefer the address variant when available (newer SDK style).
        factory_addr = core.interpret_url(conference_factory_uri, True)
        if factory_addr is not None and hasattr(params, "audio_video_conference_factory_address"):
            params.audio_video_conference_factory_address = factory_addr
        elif hasattr(params, "conference_factory_uri"):
            params.conference_factory_uri = conference_factory_uri

    # IMPORTANT: do NOT set lime_server_url on AccountParams here.
    # Doing so triggers the LIME bootstrap immediately after add_account(),
    # BEFORE the contact address is established. On networks where the LIME
    # endpoint isn't reachable on the first attempt, that path corrupts
    # internal state and SEGVs (observed against lime.linphone.org).
    # We set lime_x3dh_server_url at Core level instead (see core.py) — that
    # value is consulted lazily, after a successful registration.

    account = core.create_account(params)
    core.add_account(account)
    core.default_account = account

    # A server-conference focus running with security_level=EndToEnd rejects
    # incoming INVITEs whose caller does NOT advertise "lime" in
    # +org.linphone.specs (liblinphone/src/conference/server-conference.cpp:3161
    # ServerConference::checkClientCompatibility — 488 Not acceptable here,
    # "Lime (end to end encryption) is required to use this service"). The
    # default spec set produced by add_account is just "conference/2.0"; we
    # mirror the iOS/Android app's full set so the focus accepts our call.
    core.linphone_specs_list = [
        "conference/2.0",
        "groupchat/1.2",
        "ephemeral/1.1",
        "lime",
    ]

    # AuthInfo for HTTP-digest SIP registration. Signature in this pylinphone
    # build is create_auth_info(username, access_token, realm); password and
    # other fields are set on the instance afterwards.
    user = identity.username
    auth = linphone.Factory.get().create_auth_info(user, None, domain)
    auth.password = password
    auth.username = user
    auth.domain = domain
    auth.realm = domain
    core.add_auth_info(auth)

    # RegistrationState enum is an IntEnum in this pylinphone build, so the
    # underlying value (Ok=2, Failed=4, Cleared=3) is the safest thing to
    # compare against — .name returns "RegistrationStateOk" etc., not "Ok".
    OK = linphone.RegistrationState.RegistrationStateOk
    FAILED = linphone.RegistrationState.RegistrationStateFailed
    CLEARED = linphone.RegistrationState.RegistrationStateCleared

    log.info("registering %s via %s", sip_uri, server_uri)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        core.iterate()
        state = account.state
        if state == OK:
            log.info("account registered (state=Ok)")
            return account
        if state == FAILED:
            raise RuntimeError(f"registration failed (state={state!r})")
        if state == CLEARED:
            raise RuntimeError(f"account got Cleared before reaching Ok (state={state!r})")
        time.sleep(0.05)
    raise TimeoutError(f"registration did not complete within {timeout}s (last state={account.state!r})")
