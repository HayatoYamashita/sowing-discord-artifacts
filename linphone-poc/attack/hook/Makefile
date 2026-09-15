# Build libattack_hook.dylib for DYLD_INSERT_LIBRARIES injection.
#
# Usage:
#   make            # → libattack_hook.dylib in this directory
#   make smoke      # → load the dylib into /usr/bin/true and verify the
#                     ctor message appears (proves the interposer parses)
#
# At runtime:
#   DYLD_INSERT_LIBRARIES=$(pwd)/libattack_hook.dylib \
#   DYLD_FALLBACK_LIBRARY_PATH=$(pwd)/../../build/sdk-install/lib \
#     python -m streamer ...

DYLIB := libattack_hook.dylib
SRC   := libattack_hook.c

SDK_INSTALL := ../../build/sdk-install

CC      := clang
CFLAGS  := -O2 -Wall -Wextra -std=c11 -fPIC -dynamiclib
CFLAGS_TEST := -O2 -Wall -Wextra -std=c11 -I$(SDK_INSTALL)/include
LDFLAGS := -undefined dynamic_lookup -compatibility_version 1.0 -current_version 1.0
MBEDTLS_LIBS := \
    $(SDK_INSTALL)/lib/libmbedtls.a \
    $(SDK_INSTALL)/lib/libmbedx509.a \
    $(SDK_INSTALL)/lib/libmbedcrypto.a

.PHONY: all clean smoke smoke_test ambig_vectors equiv bench bench_c bench_sage check-sdk

# Sentinel: every binary in this Makefile links against mbedtls .a archives
# shipped inside the linphone-sdk install tree. Reviewers who try to build
# the hook or run the cryptographic validation before building the SDK would
# otherwise see an opaque clang error about a missing .a file. This target
# fires first with a clear "build the SDK first" message.
check-sdk:
	@if [ ! -f "$(SDK_INSTALL)/lib/libmbedcrypto.a" ]; then \
	  echo ""; \
	  echo "ERROR: linphone-sdk has not been built yet."; \
	  echo "       Expected: $(SDK_INSTALL)/lib/libmbedcrypto.a"; \
	  echo ""; \
	  echo "  Run, from the poc-linphone repository root:"; \
	  echo "      KEEP_PATCHES_APPLIED=1 ./scripts/build_linphone_sdk.sh"; \
	  echo ""; \
	  echo "  The hook and cryptographic validation reuse mbedtls.a from"; \
	  echo "  that build; see README.md for the full reproduction path."; \
	  echo ""; \
	  exit 1; \
	fi

all: check-sdk $(DYLIB) libfake_srtp.dylib libfake_ms.dylib smoke_test test_attack_crypto bench_attack_crypto test_e2e_adversary

$(DYLIB): check-sdk $(SRC) attack_crypto.c attack_crypto.h adversary_nals.c adversary_nals.h
	$(CC) $(CFLAGS) -I$(SDK_INSTALL)/include $(LDFLAGS) \
	    -o $@ $(SRC) attack_crypto.c adversary_nals.c $(MBEDTLS_LIBS)

test_attack_crypto: check-sdk test_attack_crypto.c attack_crypto.c attack_crypto.h
	$(CC) $(CFLAGS_TEST) -o $@ test_attack_crypto.c attack_crypto.c $(MBEDTLS_LIBS)

bench_attack_crypto: check-sdk bench_attack_crypto.c attack_crypto.c attack_crypto.h
	$(CC) $(CFLAGS_TEST) -o $@ bench_attack_crypto.c attack_crypto.c $(MBEDTLS_LIBS)

test_e2e_adversary: check-sdk test_e2e_adversary.c attack_crypto.c attack_crypto.h \
                    adversary_nals.c adversary_nals.h
	$(CC) $(CFLAGS_TEST) -o $@ test_e2e_adversary.c attack_crypto.c \
	    adversary_nals.c $(MBEDTLS_LIBS)

ambig_vectors.json: dump_ambig_vectors.sage
	cd ../.. && sage attack/hook/dump_ambig_vectors.sage > attack/hook/ambig_vectors.json

equiv: test_attack_crypto ambig_vectors.json
	./test_attack_crypto < ambig_vectors.json

bench_c: bench_attack_crypto
	./bench_attack_crypto

bench_sage:
	cd ../.. && sage attack/hook/bench_sage.sage

bench: bench_c bench_sage

libfake_srtp.dylib: libfake_srtp.c
	$(CC) -O2 -Wall -Wextra -std=c11 -fPIC -dynamiclib \
	    -install_name @rpath/libfake_srtp.dylib \
	    -o $@ $<

libfake_ms.dylib: libfake_ms.c libfake_srtp.dylib
	$(CC) -O2 -Wall -Wextra -std=c11 -fPIC -dynamiclib \
	    -install_name @rpath/libfake_ms.dylib \
	    -Wl,-rpath,$(PWD) -L$(PWD) -lfake_srtp \
	    -o $@ libfake_ms.c

smoke_test: smoke_test.c libfake_ms.dylib libfake_srtp.dylib
	$(CC) -O2 -Wall -Wextra -std=c11 \
	    -Wl,-rpath,$(PWD) -L$(PWD) -lfake_ms -lfake_srtp \
	    -o $@ smoke_test.c

smoke: $(DYLIB) smoke_test
	DYLD_INSERT_LIBRARIES=$(PWD)/$(DYLIB) ./smoke_test

clean:
	rm -f $(DYLIB) libfake_ms.dylib libfake_srtp.dylib smoke_test \
	      test_attack_crypto bench_attack_crypto ambig_vectors.json
