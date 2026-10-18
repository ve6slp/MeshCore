SELF := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT := $(abspath $(dir $(SELF))/../..)
BUILD := $(ROOT)/.tmp/v4-nrf-boot
TMPDIR := $(BUILD)
export TMPDIR
export TMP := $(TMPDIR)
export TEMP := $(TMPDIR)
CC ?= cc
CXX ?= c++
PYTHON ?= python3
BOOT := $(ROOT)/bootloader/xiao_nrf52840_ota
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -Wno-unused-function -Wno-sign-compare \
  -Wno-unterminated-string-initialization -I$(ROOT)/src/ota/trust/third_party/ed25519 \
  -I$(BOOT)/include -I$(BOOT)/src -I$(BOOT)/tests -I$(BOOT)/third_party/tweetnacl
SOURCES := $(addprefix $(BOOT)/src/,xiao_ota_boot_io.c xiao_ota_record.c xiao_ota_sha256.c \
  xiao_ota_ed25519_tweetnacl.c xiao_ota_boot_info.c) \
  $(BOOT)/third_party/tweetnacl/tweetnacl.c $(BOOT)/tests/crc16_host.c \
  $(BOOT)/tests/fake_io.c $(BOOT)/tests/v4_boot_process.c
CXXSOURCES := $(ROOT)/scripts/tests/native/ota_v4_nrf_boot.cpp \
  $(ROOT)/src/helpers/ota/OtaV4Package.cpp $(ROOT)/src/helpers/ota/OtaV4Receiver.cpp \
  $(ROOT)/src/helpers/ota/third_party/lzma/LzmaDec.c $(ROOT)/src/helpers/ota/third_party/lzma/Bra.c
HEADERS := $(shell find $(ROOT)/src/helpers/ota $(ROOT)/src/ota $(BOOT)/include $(BOOT)/src -name '*.h')
PROFILES := xiao-role0 xiao-role1 solar-role0 solar-role1

.PHONY: test build
test: build
	cd "$(ROOT)" && OTA_V4_NRF_BOOT_DIR="$(BUILD)" PYTHONPATH=scripts:scripts/tests \
	  $(PYTHON) -m unittest -v test_ota_v4_nrf_boot
build: $(BUILD)/receiver $(addprefix $(BUILD)/,$(PROFILES))
$(BUILD):
	@mkdir -p "$@"
$(BUILD)/receiver: $(CXXSOURCES) $(HEADERS) $(SELF) \
  $(ROOT)/test/test_lora_ota_storage/FakeNorFlash.h $(wildcard $(ROOT)/test/mocks/*.h) | $(BUILD)
	$(CXX) -std=c++17 -O2 -g -Wall -Wextra -Werror -Wno-unused-function \
	  -DNRF52840_XXAA -I"$(ROOT)/src" -isystem "$(ROOT)/test/mocks" $(CXXSOURCES) -o "$@"
$(BUILD)/xiao-role0: TARGET = XIAO_OTA_TARGET_XIAO_NRF52840
$(BUILD)/xiao-role1: TARGET = XIAO_OTA_TARGET_XIAO_NRF52840
$(BUILD)/solar-role0: TARGET = XIAO_OTA_TARGET_SENSECAP_SOLAR_P1
$(BUILD)/solar-role1: TARGET = XIAO_OTA_TARGET_SENSECAP_SOLAR_P1
$(BUILD)/xiao-role0 $(BUILD)/solar-role0: ROLE = 0
$(BUILD)/xiao-role1 $(BUILD)/solar-role1: ROLE = 1
$(addprefix $(BUILD)/,$(PROFILES)): $(SOURCES) $(HEADERS) $(SELF) $(BOOT)/tests/fake_io.h | $(BUILD)
	$(CC) $(CFLAGS) -DXIAO_OTA_BOARD_TARGET=$(TARGET) -DXIAO_OTA_COMPILED_ROLE_ID=$(ROLE) \
	  $(SOURCES) -o "$@"
