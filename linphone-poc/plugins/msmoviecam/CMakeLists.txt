############################################################################
# msmoviecam: mediastreamer2 webcam plugin reading an mp4/mov via ffmpeg.
# Built standalone against an already-built linphone-sdk (mac-arm64 preset).
#
# Usage:
#   cmake -S . -B build \
#         -DCMAKE_PREFIX_PATH=<linphone-sdk-build>/install \
#         -DCMAKE_INSTALL_PREFIX=<plugin-install-prefix>
#   cmake --build build --config RelWithDebInfo
#   cmake --install build
#
# Produces:  <prefix>/lib/mediastreamer/plugins/libmsmoviecam.dylib
############################################################################

cmake_minimum_required(VERSION 3.22)
project(msmoviecam VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET default)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# OrtpConfig.cmake (upstream) loads OrtpTargets BEFORE calling
# find_dependency(BCToolbox). Without bctoolbox defined first, the targets
# check sets Ortp_FOUND=FALSE, which cascades to Mediastreamer2_FOUND=FALSE.
# Pre-load BCToolbox and Ortp here so the targets exist by the time
# Mediastreamer2Config's chain validates them.
find_package(BCToolbox REQUIRED CONFIG)
find_package(Ortp REQUIRED CONFIG)
find_package(Mediastreamer2 REQUIRED CONFIG)

add_library(msmoviecam SHARED src/msmoviecam.c)

target_link_libraries(msmoviecam PRIVATE ${Mediastreamer2_TARGET})

# IMPORTANT: mediastreamer2's plugin loader (mediastreamer2/src/base/msfactory.c)
# scans for `libms*.<PLUGINS_EXT>`, with PLUGINS_EXT defaulting to ".so" even on
# macOS — and matches the init symbol as "<basename-without-ext>_init".
# We must therefore ship the plugin as `libmsmoviecam.so` (NOT .dylib) and define
# `libmsmoviecam_init` (not `libmsmoviecam.dylib_init` or similar). The existing
# `libmswebrtc.so` next to ours confirms the convention.
set_target_properties(msmoviecam PROPERTIES
	PREFIX "lib"
	OUTPUT_NAME "msmoviecam"
	SUFFIX ".so"
	MACOSX_RPATH ON
)

if(NOT MSVC)
	target_compile_options(msmoviecam PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

install(TARGETS msmoviecam
	LIBRARY DESTINATION "${Mediastreamer2_PLUGINS_DIR}"
)
