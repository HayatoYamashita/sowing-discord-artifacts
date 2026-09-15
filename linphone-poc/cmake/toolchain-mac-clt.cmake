# Command-Line-Tools-compatible drop-in replacement for linphone-sdk's
# upstream macOS toolchain.
#
# The upstream toolchain (cmake/toolchains/toolchain-mac-common.cmake) calls
#   xcrun --show-sdk-platform-path
# which only works with a full Xcode.app installation — Command Line Tools
# alone fails with:
#   xcrun: error: unable to lookup item 'PlatformPath' from command line tools
# This file does the same job using only `xcrun --show-sdk-path` (which works
# on plain Command Line Tools).
#
# Pass it via -DCMAKE_TOOLCHAIN_FILE=<this file> to the linphone-sdk configure
# step (without the mac-arm64 preset, since that preset hard-codes the Xcode
# generator which also needs full Xcode).

if(NOT APPLE)
	message(FATAL_ERROR "This toolchain targets macOS only.")
endif()

execute_process(COMMAND xcode-select -print-path
	RESULT_VARIABLE _XCSEL_RC OUTPUT_VARIABLE _XCSEL_PATH
	OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _XCSEL_RC EQUAL 0)
	message(FATAL_ERROR "xcode-select failed. Install Command Line Tools: xcode-select --install")
endif()

execute_process(COMMAND xcrun --sdk macosx --show-sdk-path
	RESULT_VARIABLE _SDKP_RC OUTPUT_VARIABLE _SDK_PATH
	OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _SDKP_RC EQUAL 0 OR _SDK_PATH STREQUAL "")
	message(FATAL_ERROR "xcrun --show-sdk-path failed. Try: xcode-select --install")
endif()

execute_process(COMMAND xcrun --sdk macosx --show-sdk-version
	OUTPUT_VARIABLE _SDK_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND xcrun --sdk macosx --find clang
	RESULT_VARIABLE _CLANG_RC OUTPUT_VARIABLE _CLANG_PATH
	OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _CLANG_RC EQUAL 0)
	message(FATAL_ERROR "xcrun --find clang failed.")
endif()
get_filename_component(_TC_BIN "${_CLANG_PATH}" DIRECTORY)

set(CMAKE_SYSTEM_NAME      "Darwin")
set(CMAKE_SYSTEM_VERSION   "${_SDK_VERSION}")
set(CMAKE_SYSTEM_PROCESSOR "arm64")
set(CMAKE_OSX_ARCHITECTURES "arm64")
set(CMAKE_OSX_SYSROOT      "${_SDK_PATH}")

set(CMAKE_C_COMPILER   "${_TC_BIN}/clang")
set(CMAKE_CXX_COMPILER "${_TC_BIN}/clang++")
set(CMAKE_AR           "${_TC_BIN}/ar"      CACHE FILEPATH "ar")
set(CMAKE_RANLIB       "${_TC_BIN}/ranlib"  CACHE FILEPATH "ranlib")
set(CMAKE_LINKER       "${_TC_BIN}/ld"     CACHE FILEPATH "linker")
set(CMAKE_NM           "${_TC_BIN}/nm"     CACHE FILEPATH "nm")
set(CMAKE_STRIP        "${_TC_BIN}/strip"  CACHE FILEPATH "strip")

set(CMAKE_FIND_ROOT_PATH "${CMAKE_OSX_SYSROOT}" "${CMAKE_INSTALL_PREFIX}")

message(STATUS "[clt-toolchain] CMAKE_OSX_SYSROOT       = ${CMAKE_OSX_SYSROOT}")
message(STATUS "[clt-toolchain] CMAKE_SYSTEM_VERSION    = ${CMAKE_SYSTEM_VERSION}")
message(STATUS "[clt-toolchain] CMAKE_C_COMPILER        = ${CMAKE_C_COMPILER}")
