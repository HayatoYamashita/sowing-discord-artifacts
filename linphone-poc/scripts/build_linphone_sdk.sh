#!/usr/bin/env bash
# One-shot build for the AE artifact (Apple Silicon, Command-Line-Tools-only).
#
#   1) builds linphone-sdk with the Python wrapper enabled,
#      out-of-tree, installing into ./build/sdk-install
#   2) builds the local msmoviecam mediastreamer2 plugin against that install,
#      placing libmsmoviecam.so into the SDK's plugin directory.
#
# The SDK source tree under third_party/linphone-sdk/ is vendored into
# this repository as a git subtree (commit 7d5fe98a18 of the upstream
# Linphone SDK). The build only applies the two patches under patches/
# to that tree (and reverts them on exit unless KEEP_PATCHES_APPLIED=1).
# Every build artifact is written under ./build/.
#
# Unlike the upstream `mac-arm64` preset, this script does NOT require a full
# Xcode.app — it ships a Command-Line-Tools-compatible toolchain at
# cmake/toolchain-mac-clt.cmake and uses Ninja instead of the Xcode generator.

set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Default: linphone-sdk source is vendored under third_party/linphone-sdk
# via git subtree. Reviewers with a different checkout (e.g. a pre-populated
# tree that already has all .gitmodules resolved) can override via SDK_SRC.
SDK_SRC="${SDK_SRC:-${POC_DIR}/third_party/linphone-sdk}"

BUILD_ROOT="${BUILD_ROOT:-${POC_DIR}/build}"
SDK_BUILD_DIR="${BUILD_ROOT}/sdk-build"
SDK_INSTALL_DIR="${BUILD_ROOT}/sdk-install"
PLUGIN_BUILD_DIR="${BUILD_ROOT}/plugin-build"
VENV_DIR="${BUILD_ROOT}/venv"

TOOLCHAIN="${POC_DIR}/cmake/toolchain-mac-clt.cmake"
CFG="${CFG:-RelWithDebInfo}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"

c_blue=$'\033[1;34m'; c_red=$'\033[1;31m'; c_reset=$'\033[0m'
log()  { printf '%s[build]%s %s\n'   "$c_blue" "$c_reset" "$*"; }
fail() { printf '%s[build]%s %s\n'   "$c_red"  "$c_reset" "$*" >&2; exit 1; }

[[ -f "${TOOLCHAIN}" ]] || fail "missing toolchain file: ${TOOLCHAIN}"

[[ -d "${SDK_SRC}" ]] || fail "linphone-sdk source not found at ${SDK_SRC} (set SDK_SRC to override; the default is third_party/linphone-sdk, vendored as a git subtree)"
[[ -f "${SDK_SRC}/CMakeLists.txt" ]] || fail "no CMakeLists at ${SDK_SRC}"

mkdir -p "${BUILD_ROOT}"

############################################################################
# linphone-sdk submodules.
#
# The top-level linphone-sdk tree is vendored as a git subtree under
# third_party/linphone-sdk/. The submodule entries inside that tree
# (bcg729, bcmatroska2, external/mbedtls, external/srtp, ...) are NOT
# tracked by the subtree merge, so each submodule directory exists as
# an empty placeholder until populated.
#
# When SDK_SRC is itself a git checkout (the historical "clone into
# ./linphone-sdk/" workflow), we can use `git submodule update` to
# populate the placeholders. When SDK_SRC has no .git (the new subtree
# vendoring), the script delegates submodule population to whatever
# external mechanism the reviewer arranged before invoking the build
# (a separate vendored snapshot, an out-of-band rsync from a peer
# checkout, etc.).
############################################################################
if [[ -d "${SDK_SRC}/.git" ]]; then
	log "ensuring linphone-sdk submodules are checked out (with retry)"
	count_bad_submodules() {
		( cd "${SDK_SRC}" && git submodule status --recursive 2>/dev/null | grep -c '^[+-]' ) || true
	}
	count_wrong_commit() {
		( cd "${SDK_SRC}" && git submodule status --recursive 2>/dev/null | grep -c '^+' ) || true
	}
	list_bad_submodules() {
		( cd "${SDK_SRC}" && git submodule status --recursive 2>/dev/null | awk '/^[+-]/ {print $2}' ) || true
	}

	MAX_TRIES="${SDK_SUBMODULE_TRIES:-30}"
	RETRY_DELAY="${SDK_SUBMODULE_RETRY_DELAY:-5}"
	for try in $(seq 1 ${MAX_TRIES}); do
		bad_submodules="$(count_bad_submodules)"
		if [[ "${bad_submodules}" -eq 0 ]]; then
			break
		fi
		log "  attempt ${try}/${MAX_TRIES}: ${bad_submodules} submodules missing or at non-locked commits — retrying"
		while IFS= read -r submodule_path; do
			[[ -n "${submodule_path}" ]] || continue
			log "    updating ${submodule_path}"
			( cd "${SDK_SRC}" && git submodule update --init --recursive --force --depth=1 -- "${submodule_path}" ) || true
		done < <(list_bad_submodules)
		sleep "${RETRY_DELAY}"
	done

	bad_submodules="$(count_bad_submodules)"
	wrong="$(count_wrong_commit)"
	if [[ "${bad_submodules}" -ne 0 ]]; then
		fail "after ${MAX_TRIES} attempts, ${bad_submodules} submodules are still missing or at non-locked commits. Re-run the script, or manually run: cd ${SDK_SRC} && git submodule update --init --recursive --force"
	fi
	log "submodules: all locked revisions checked out; ${wrong} at non-locked commit"
else
	log "SDK_SRC has no .git (vendored snapshot) — skipping submodule update."
	log "  CMake will fail if any submodule directory is empty. If that happens,"
	log "  populate third_party/linphone-sdk's submodules out-of-band (e.g. rsync"
	log "  from a sibling clone) before re-invoking this script."
fi

############################################################################
# Apply PoC patches to the linphone-sdk working tree before configuring.
# Patches under poc-linphone/patches/ contain the focus-side attack hook
# (paper §5.1 Anet role) added to ekt-server. Set KEEP_PATCHES_APPLIED=1 to
# leave the patches in the working tree after the build finishes (useful
# while iterating on the patch contents). Default behaviour is to revert
# patches at script exit, so the linphone-sdk tree is restored to clean.
############################################################################
PATCH_DIR="${POC_DIR}/patches"
APPLIED_PATCHES=()
revert_applied_patches() {
	local rc=$?
	if [[ "${KEEP_PATCHES_APPLIED:-0}" == "1" ]]; then
		log "KEEP_PATCHES_APPLIED=1: leaving patches in ${SDK_SRC} (not reverting)"
		return $rc
	fi
	for p in "${APPLIED_PATCHES[@]}"; do
		log "reverting patch: ${p##*/}"
		( cd "${SDK_SRC}" && git apply -R "$p" ) || true
	done
	return $rc
}
trap revert_applied_patches EXIT

if [[ -d "${PATCH_DIR}" ]]; then
	shopt -s nullglob
	for p in "${PATCH_DIR}"/*.patch; do
		log "applying patch: ${p##*/}"
		# --check first so we don't half-apply if the tree is already dirty
		if ! ( cd "${SDK_SRC}" && git apply --check "$p" ) 2>/dev/null; then
			# Already applied? Detect by trying reverse-check.
			if ( cd "${SDK_SRC}" && git apply --check -R "$p" ) 2>/dev/null; then
				log "  -> already applied (reverse-check passes); skipping"
				APPLIED_PATCHES+=( "$p" )  # still need revert at exit
				continue
			fi
			fail "patch ${p##*/} cannot be applied to ${SDK_SRC} (working tree dirty or conflicts)"
		fi
		( cd "${SDK_SRC}" && git apply "$p" ) || fail "git apply failed for ${p##*/}"
		APPLIED_PATCHES+=( "$p" )
	done
	shopt -u nullglob
	log "patches applied: ${#APPLIED_PATCHES[@]} (will revert at script exit unless KEEP_PATCHES_APPLIED=1)"
else
	log "no patches/ directory under ${POC_DIR} — building stock SDK"
fi

log "POC_DIR          = ${POC_DIR}"
log "SDK_SRC          = ${SDK_SRC}  (read-only)"
log "SDK_BUILD_DIR    = ${SDK_BUILD_DIR}"
log "SDK_INSTALL_DIR  = ${SDK_INSTALL_DIR}"
log "PLUGIN_BUILD_DIR = ${PLUGIN_BUILD_DIR}"
log "VENV_DIR         = ${VENV_DIR}"
log "TOOLCHAIN        = ${TOOLCHAIN}"
log "CFG=${CFG}  JOBS=${JOBS}"

# --- fail-fast precheck: announce *every* missing dependency before exiting
# instead of stopping on the first one. A reviewer should be able to fix the
# whole list in one go before re-running the script.
PRECHECK_FAIL=()
require() {
	if ! command -v "$1" >/dev/null 2>&1; then
		PRECHECK_FAIL+=("$1   ($2)")
	fi
}
require cmake   "brew install cmake"
require ninja   "brew install ninja"
require yasm    "brew install yasm"
require nasm    "brew install nasm"
require doxygen "brew install doxygen"
require ffmpeg  "brew install ffmpeg   (runtime dependency of the msmoviecam plugin, AND of the IDR-only adversary stream re-encode in §5.4.2.1)"
require python3 "use python.org / pyenv / brew (>= 3.10)"
require xcrun   "xcode-select --install"

# Architecture: the cmake toolchain forces -arch arm64, so building on an
# x86 macOS host would silently produce x86 binaries that don't match.
HOST_ARCH="$(uname -m)"
if [[ "${HOST_ARCH}" != "arm64" ]]; then
	PRECHECK_FAIL+=("host arch is ${HOST_ARCH}, but cmake/toolchain-mac-clt.cmake targets arm64. Run on Apple Silicon.")
fi

# Python >= 3.10. pyproject.toml enforces it for the installed package,
# but the venv is created from the system python3 before any
# pyproject is consulted, so we have to check here too.
if command -v python3 >/dev/null 2>&1; then
	PY_VER_OK="$(python3 -c 'import sys; print(1 if sys.version_info[:2] >= (3,10) else 0)' 2>/dev/null || echo 0)"
	if [[ "${PY_VER_OK}" != "1" ]]; then
		PY_RAW="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo unknown)"
		PRECHECK_FAIL+=("python3 ${PY_RAW} is too old — need >= 3.10")
	fi
fi

# The pinned pip-requirements manifest must exist.
if [[ ! -f "${POC_DIR}/scripts/sdk-build-requirements.txt" ]]; then
	PRECHECK_FAIL+=("missing scripts/sdk-build-requirements.txt (the pinned manifest for pip deps inside the venv)")
fi

if (( ${#PRECHECK_FAIL[@]} > 0 )); then
	printf '%s[build]%s missing host prerequisites:\n' "$c_red" "$c_reset" >&2
	for line in "${PRECHECK_FAIL[@]}"; do
		printf '  - %s\n' "${line}" >&2
	done
	printf '\nAfter fixing the above, re-run %s\n' "$0" >&2
	exit 1
fi

############################################################################
# Self-contained Python venv (avoids PEP 668 "externally-managed-environment")
############################################################################
if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
	log "creating Python venv at ${VENV_DIR}"
	python3 -m venv "${VENV_DIR}"
fi
PY="${VENV_DIR}/bin/python3"
PY_VER="$(${PY} -c 'import sys; print("%d.%d"%sys.version_info[:2])')"
log "python3 (venv) = ${PY}  (v${PY_VER})"

log "ensuring pip build deps inside venv (pinned by scripts/sdk-build-requirements.txt)"
# We don't auto-upgrade pip — its own minor releases have repeatedly
# changed wheel-resolution semantics in ways that would invalidate the
# pinned requirements below.  The version that ships with the venv
# created by `python3 -m venv` is sufficient.
"${PY}" -m pip install --quiet -r "${POC_DIR}/scripts/sdk-build-requirements.txt"

############################################################################
# Common cache vars taken from the linphone-sdk mac-common preset.
# We can't use --preset=mac-arm64 here because it forces the Xcode generator
# (requires full Xcode.app); we use Ninja + the in-tree CLT-compatible
# toolchain instead.
############################################################################
SDK_CACHE_ARGS=(
	# Pin the version strings that bctoolbox/cmake/BCToolboxCMakeUtils.cmake
	# would otherwise derive by invoking `git describe` inside ${SDK_SRC}.
	# That call fails when the SDK is vendored as a subtree, because
	# `git describe` then returns a tag from the surrounding poc-linphone
	# repo (e.g. "proposed-attack-complete-25-g…"), which does not match
	# the major.minor.patch grammar bctoolbox expects.  Hard-coding the
	# values matches what `git describe` returns at the pinned upstream
	# commit (7d5fe98a18).
	-DLINPHONESDK_VERSION=5.5.0-alpha-31511-g7d5fe98a18
	-DLINPHONESDK_STATE=snapshots
	-DLINPHONESDK_BRANCH=master
	# Python wheel version: bypass cmake/python/GenerateWheel.cmake's
	# git describe via the gate added by 0003-…-honor-prepinned-wheel-version.
	# Value uses the PEP 440 form the upstream function produces from
	# `5.5.0-alpha-31511-g7d5fe98a18`.
	-DWHEEL_LINPHONESDK_VERSION_PINNED=5.5.0.alpha31511+git.7d5fe98a18
	-DBUILD_BCG729_SHARED_LIBS=OFF
	-DBUILD_BCUNIT_SHARED_LIBS=OFF
	-DBUILD_BV16_SHARED_LIBS=OFF
	-DBUILD_BZRTP_SHARED_LIBS=OFF
	-DBUILD_DECAF_SHARED_LIBS=OFF
	-DBUILD_GSM_SHARED_LIBS=OFF
	-DBUILD_JSONCPP_SHARED_LIBS=OFF
	-DBUILD_LIBJPEGTURBO_SHARED_LIBS=OFF
	-DBUILD_LIBSRTP2_SHARED_LIBS=OFF
	-DBUILD_LIBXML2_SHARED_LIBS=OFF
	-DBUILD_LIBYUV_SHARED_LIBS=OFF
	-DBUILD_MBEDTLS_SHARED_LIBS=OFF
	-DBUILD_OPENLDAP_SHARED_LIBS=OFF
	-DBUILD_OPUS_SHARED_LIBS=OFF
	-DBUILD_SOCI_SHARED_LIBS=OFF
	-DBUILD_SPEEX_SHARED_LIBS=OFF
	-DBUILD_SQLITE3_SHARED_LIBS=OFF
	-DBUILD_XERCESC_SHARED_LIBS=OFF
	-DBUILD_ZLIB_SHARED_LIBS=OFF
	-DENABLE_SCREENSHARING=OFF       # disabled: ScreenCaptureKit needs full Xcode SDK + signing
	-DENABLE_SWIFT_WRAPPER=OFF       # don't need Swift binding for our Python CLI
	-DENABLE_SWIFT_WRAPPER_COMPILATION=OFF
	-DENABLE_VIDEOTOOLBOX=ON       # macOS HW H.264 + H.265 via VideoToolbox
	-DENABLE_OPENH264=OFF          # avoid ENABLE_NON_FREE_FEATURES dependency; VideoToolbox covers H.264
	-DENABLE_AV1=OFF               # not needed for H.264/H.265 PoC; drops meson + perl requirements
	-DENABLE_UNIT_TESTS=OFF
	-DENABLE_TOOLS=OFF
	-DENABLE_PYTHON_WRAPPER=ON
	-DPython3_EXECUTABLE="${PY}"
	# EKT server plugin (linphone_ektserver). Required for the focus daemon
	# (python -m streamer.focus) to host LinphoneConferenceSecurityLevelEndToEnd
	# conferences. liblinphone's ServerConference::checkServerConfiguration
	# (server-conference.cpp:840) returns 488 Not Acceptable to clients if this
	# plugin is missing — that is exactly the failure mode of sip.linphone.org's
	# public SFU.
	-DENABLE_EKT_SERVER_PLUGIN=ON
	# The EKT server plugin links against the C++ wrapper (linphone::Core,
	# linphone::Conference, …). liblinphone/CMakeLists.txt defaults
	# ENABLE_CXX_WRAPPER to YES, but only as a leaf `option()`; the
	# superproject's `linphonesdk_dependent_option` machinery does not seed
	# it on the cache, so it ends up disabled in some configurations. Force
	# it ON here to keep the EKT plugin's CMake configure step happy
	# (ekt-server/CMakeLists.txt:58 `find_package(LibLinphoneCxx ...)`).
	-DENABLE_CXX_WRAPPER=ON
)

############################################################################
# 1) linphone-sdk
############################################################################
log "[1/2] configuring linphone-sdk"
cmake -S "${SDK_SRC}" -B "${SDK_BUILD_DIR}" \
	-G Ninja \
	-DCMAKE_BUILD_TYPE="${CFG}" \
	-DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
	-DCMAKE_INSTALL_PREFIX="${SDK_INSTALL_DIR}" \
	-DLINPHONESDK_DIR="${SDK_SRC}" \
	"${SDK_CACHE_ARGS[@]}"

log "[1/2] building + installing linphone-sdk (this can take 20-40 min on first run)"
# liblinphone/wrappers/python/genwrapper.py (Python wrapper generator)
# shells out to `git describe`. With the SDK vendored as a subtree under
# third_party/linphone-sdk/, there is no .git directory inside the SDK
# source, so the call returns "fatal: not a git repository" and fails the
# build. Patch 0004 honours LINPHONESDK_VERSION from the environment in
# that script; export it here so the patched genwrapper.py picks it up.
# Also prepend the venv bin to PATH so CMake-spawned `cython` / `pdoc` resolve.
LINPHONESDK_VERSION=5.5.0-alpha-31511-g7d5fe98a18 \
PATH="${VENV_DIR}/bin:${PATH}" \
	cmake --build "${SDK_BUILD_DIR}" --config "${CFG}" --parallel "${JOBS}" --target install

############################################################################
# 2) msmoviecam plugin (in-tree, links against just-installed SDK)
############################################################################
log "[2/2] configuring msmoviecam plugin"
cmake -S "${POC_DIR}/plugins/msmoviecam" -B "${PLUGIN_BUILD_DIR}" \
	-G Ninja \
	-DCMAKE_BUILD_TYPE="${CFG}" \
	-DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
	-DCMAKE_PREFIX_PATH="${SDK_INSTALL_DIR}" \
	-DCMAKE_INSTALL_PREFIX="${SDK_INSTALL_DIR}"

log "[2/2] building + installing msmoviecam plugin"
cmake --build "${PLUGIN_BUILD_DIR}" --config "${CFG}" --parallel "${JOBS}" --target install

############################################################################
# Discover output paths and print env-var exports
############################################################################
PYLINPHONE_PATH="$(find "${SDK_INSTALL_DIR}" -name 'pylinphone*.so' -o -name 'pylinphone*.dylib' 2>/dev/null | head -n1)"
PYLINPHONE_DIR="${PYLINPHONE_PATH%/*}"
# liblinphone is installed as a macOS Framework (Frameworks/linphone.framework);
# expose the parent "Frameworks" dir via DYLD_FRAMEWORK_PATH so @rpath/...framework
# loads at runtime.
FRAMEWORKS_DIR="$(find "${SDK_INSTALL_DIR}" -type d -name 'linphone.framework' 2>/dev/null | head -n1 | xargs -I{} dirname {} || true)"
LIB_DIR="${SDK_INSTALL_DIR}/lib"
PLUGIN_DIR="$(find "${SDK_INSTALL_DIR}" -name 'libmsmoviecam.so' 2>/dev/null | head -n1 | xargs -I{} dirname {} || true)"
# liblinphone_ektserver.<ext> is installed into ${LibLinphone_PLUGINS_DIR} by
# the ekt-server CMakeLists. macOS ships shared modules as .so for module
# loading (see liblinphone src/core/core.cpp:120 LINPHONE_PLUGINS_EXT=".so"),
# but be tolerant in case the install rules ever change.
LIB_PLUGIN_DIR="$(find "${SDK_INSTALL_DIR}" \( -name 'liblinphone_ektserver.so' -o -name 'liblinphone_ektserver*.dylib' \) 2>/dev/null | head -n1 | xargs -I{} dirname {} || true)"

[[ -n "${PYLINPHONE_DIR}" ]] || fail "pylinphone .so/.dylib not found under ${SDK_INSTALL_DIR}"
[[ -n "${FRAMEWORKS_DIR}" ]] || fail "linphone.framework not found under ${SDK_INSTALL_DIR}"
[[ -n "${PLUGIN_DIR}"     ]] || fail "libmsmoviecam.so not found under ${SDK_INSTALL_DIR}"
[[ -n "${LIB_PLUGIN_DIR}" ]] || fail "liblinphone_ektserver plugin not found under ${SDK_INSTALL_DIR} — was -DENABLE_EKT_SERVER_PLUGIN=ON applied?"

# The C extension is named `pylinphone`, but the upstream Python API and our
# Python code use `import linphone`. Drop a re-export shim next to the .so
# so `import linphone` resolves to the same module.
cat > "${PYLINPHONE_DIR}/linphone.py" <<'PY'
"""Shim: expose pylinphone (Cython C extension) under the name `linphone`.

This matches the import convention used by Belledonne's own samples
(e.g. liblinphone/tools/linphone-sample.py) without modifying the SDK."""
from pylinphone import *  # noqa: F401,F403
import pylinphone as _pylinphone  # noqa: F401

# Re-export dunder attributes that `import *` would skip but callers may want.
__doc__ = _pylinphone.__doc__
__file__ = _pylinphone.__file__
PY

ENVRC="${BUILD_ROOT}/envrc"
cat > "${ENVRC}" <<EOF
# Auto-generated by scripts/build_linphone_sdk.sh
# Source this file (\`source build/envrc\`) before running \`python -m streamer\`.
#
# Activates the project-local venv (same interpreter that pylinphone was built
# against) and points the dynamic loader at the in-tree SDK install.
. "${VENV_DIR}/bin/activate"
export POC_LINPHONE_PLUGIN_DIR="${PLUGIN_DIR}"
export POC_LINPHONE_LIB_PLUGIN_DIR="${LIB_PLUGIN_DIR}"
export PYTHONPATH="${PYLINPHONE_DIR}:\${PYTHONPATH:-}"
export DYLD_FALLBACK_LIBRARY_PATH="${LIB_DIR}:\${DYLD_FALLBACK_LIBRARY_PATH:-}"
export DYLD_FALLBACK_FRAMEWORK_PATH="${FRAMEWORKS_DIR}:\${DYLD_FALLBACK_FRAMEWORK_PATH:-}"
EOF

cat <<EOF

============================================================
Build done. Outputs:
  pylinphone module : ${PYLINPHONE_DIR}/pylinphone.so
  Frameworks        : ${FRAMEWORKS_DIR}
  msmoviecam plugin : ${PLUGIN_DIR}/libmsmoviecam.so
  EKT server plugin : ${LIB_PLUGIN_DIR}/liblinphone_ektserver.so

Env-vars written to: ${ENVRC}

Activate this shell with:
  source build/envrc

Quick smoke test:
  python3 -c "import linphone; print(linphone.Factory.get())"
============================================================
EOF
