ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
TMPDIR := $(ROOT)/.tmp/v4-platform-tests
export TMPDIR
export TMP := $(TMPDIR)
export TEMP := $(TMPDIR)
CXX ?= g++
# The retained Ed25519 implementation intentionally uses signed limb shifts.
.PHONY: test
test:
	@mkdir -p "$(TMPDIR)"
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -Wno-unused-function \
	  -fsanitize=address,undefined -fno-sanitize=shift -fno-omit-frame-pointer -I"$(ROOT)/src" \
	  "$(ROOT)/test/test_lora_ota_v4_platform/test_platform.cpp" \
	  "$(ROOT)/src/helpers/ota/OtaV4Package.cpp" \
	  -o "$(TMPDIR)/platform"
	ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$(TMPDIR)/platform"
