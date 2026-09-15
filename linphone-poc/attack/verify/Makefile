# Build the libsrtp KDF compatibility tester.
# Output: ./test_kdf_compat (or run `make run` to build + execute).

SDK_INSTALL := ../../build/sdk-install

CC := clang
CFLAGS := -O2 -Wall -Wextra -std=c11 -I$(SDK_INSTALL)/include
LDFLAGS := \
    $(SDK_INSTALL)/lib/libsrtp2.a \
    $(SDK_INSTALL)/lib/libmbedtls.a \
    $(SDK_INSTALL)/lib/libmbedx509.a \
    $(SDK_INSTALL)/lib/libmbedcrypto.a

# libsrtp2 in this poc-linphone build was linked against mbedTLS (no
# OpenSSL), so we statically link the three mbed* archives. If you switch
# to a libsrtp built with OpenSSL, replace the three mbed* paths with
# -lssl -lcrypto (or the static OpenSSL archive paths).

.PHONY: all run clean
all: test_kdf_compat

test_kdf_compat: test_kdf_compat.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: test_kdf_compat
	./test_kdf_compat > vectors.json
	@echo
	@echo "[+] wrote vectors.json:"
	@cat vectors.json

clean:
	rm -f test_kdf_compat vectors.json
