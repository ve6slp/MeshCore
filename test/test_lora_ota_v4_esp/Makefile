ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
TMPDIR := $(ROOT)/.tmp/v4-esp-tests
export TMPDIR
export TMP := $(TMPDIR)
export TEMP := $(TMPDIR)
CXX ?= g++
BACKEND_SOURCE ?= $(ROOT)/variants/xiao_s3_wio/OtaEsp32Backend.cpp
SDK_HEADERS := Arduino.h Ed25519.h esp_attr.h esp_bt.h esp_flash.h esp_image_format.h \
  esp_log.h esp_ota_ops.h esp_partition.h esp_random.h esp_rom_sys.h esp_wifi.h \
  bootloader_random.h esp_arduino_version.h esp_idf_version.h esp_private/esp_clk.h \
  hal/wdt_hal.h soc/rtc.h nvs.h nvs_flash.h esp_err.h target.h

.PHONY: test regression-check
test:
	@mkdir -p "$(TMPDIR)/include"
	@for header in $(SDK_HEADERS); do \
	  mkdir -p "$(TMPDIR)/include/$$(dirname "$$header")"; \
	  printf '#include "NativeEspSdk.h"\n' > "$(TMPDIR)/include/$$header"; \
	done
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -Wno-unused-function \
	  -fsanitize=address,undefined -fno-sanitize=shift -fno-omit-frame-pointer \
	  -DESP32_PLATFORM -DMESHCORE_LORA_OTA=1 -DXIAO_S3_OTA_COMPILED_ROLE_ID=1 \
	  -DCONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=1 -DCONFIG_APP_ROLLBACK_ENABLE=1 \
	  -DMESHCORE_ESP32_OTA_STARTUP_NVS_GUARD=1 \
	  -DOTA_ESP_BACKEND_SOURCE='"$(BACKEND_SOURCE)"' $(CPPFLAGS) \
	  -I"$(TMPDIR)/include" -I"$(ROOT)/test/test_lora_ota_v4_esp" -I"$(ROOT)/src" \
	  "$(ROOT)/test/test_lora_ota_v4_esp/test_esp_backend.cpp" \
	  "$(ROOT)/src/ota/platform/Esp32FlashAdapter.cpp" \
	  "$(ROOT)/src/helpers/ota/OtaV4Package.cpp" "$(ROOT)/src/helpers/ota/OtaV4Receiver.cpp" \
	  "$(ROOT)/src/helpers/ota/third_party/lzma/LzmaDec.c" \
	  "$(ROOT)/src/helpers/ota/third_party/lzma/Bra.c" -o "$(TMPDIR)/esp-backend"
	ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$(TMPDIR)/esp-backend"

# Reintroduce each reviewed bug only in local build copies. The regression
# assertions must reject both copies, not merely pass the corrected code.
regression-check: test
	@mkdir -p "$(TMPDIR)/regression/include/ota/platform"
	@sed \
	  -e 's/api_\.readOtaMetadata(offset, out, size)/api_.read(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, out, size)/' \
	  -e 's/api_\.writeOtaMetadata(offset, bytes, size)/api_.write(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, bytes, size)/' \
	  -e 's/api_\.eraseOtaMetadata(offset, 4096)/api_.erase(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, 4096)/' \
	  "$(ROOT)/src/ota/platform/Esp32OtaMetadataAdapter.h" \
	  > "$(TMPDIR)/regression/include/ota/platform/Esp32OtaMetadataAdapter.h"
	@ulimit -c 0; if $(MAKE) --no-print-directory -f "$(lastword $(MAKEFILE_LIST))" test \
	  CPPFLAGS='-I"$(TMPDIR)/regression/include"' > "$(TMPDIR)/regression/metadata.log" 2>&1; then \
	  echo 'ERROR: old metadata wiring escaped regression tests'; exit 1; \
	fi
	@grep -q 'actualMetadataCapability.*Assertion.*store.recover' "$(TMPDIR)/regression/metadata.log"
	@sed 's/if (!bound \&\& contextNormal())/if (!matches \&\& contextNormal())/' \
	  "$(ROOT)/variants/xiao_s3_wio/OtaEsp32Backend.cpp" > "$(TMPDIR)/regression/backend.cpp"
	@ulimit -c 0; if $(MAKE) --no-print-directory -f "$(lastword $(MAKEFILE_LIST))" test \
	  BACKEND_SOURCE="$(TMPDIR)/regression/backend.cpp" > "$(TMPDIR)/regression/rollback.log" 2>&1; then \
	  echo 'ERROR: old rollback condition escaped regression tests'; exit 1; \
	fi
	@grep -q 'sameImageTransaction.*Assertion.*rolledBack.lifecycle' "$(TMPDIR)/regression/rollback.log"
	@echo 'Both original ESP bugs rejected by the production-wiring regressions'
	@$(MAKE) --no-print-directory -f "$(lastword $(MAKEFILE_LIST))" test
