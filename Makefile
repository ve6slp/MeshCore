PLATFORMIO ?= pio
PYTHON ?= python3
.DEFAULT_GOAL := build
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

# ENV selects an ordinary PlatformIO environment; OTA is never added implicitly.
ENV ?=
NATIVE_TEST_ENVS ?= native native_kiss_modem
OTA_TEST_FILTER ?= test_lora_ota_*
# Optional Google Test selector for native OTA targets, e.g. OTA_GTEST_FILTER='LoraOtaRoutedRetry.*'.
OTA_GTEST_FILTER ?=
OTA_GTEST_ENV = $(if $(strip $(OTA_GTEST_FILTER)),GTEST_FILTER='$(OTA_GTEST_FILTER)')
OTA_NRF52_TARGET_ENVS ?= Xiao_nrf52_companion_radio_ota_usb Xiao_nrf52_repeater_ota_usb SenseCap_Solar_companion_radio_ota_usb SenseCap_Solar_repeater_ota_usb
OTA_ESP32_TARGET_ENVS ?= Xiao_S3_WIO_companion_radio_ota_usb Xiao_S3_WIO_repeater_ota_usb
OTA_TARGET_ENVS ?= $(OTA_NRF52_TARGET_ENVS) $(OTA_ESP32_TARGET_ENVS)

OTA_ARGS ?=
OTA_ARTIFACT_DIR ?=
OTA_DEVICE_PORT ?=
OTA_DEVICE_DTR ?= 0
OTA_DEVICE_TIMEOUT ?= 5
XIAO_OTA_PAIR_BOARD ?=
XIAO_OTA_PAIR_ROLE_ID ?=
XIAO_OTA_PAIR_DIR ?= $(TMPDIR)/ota-boot-builds/$(XIAO_OTA_PAIR_BOARD)-role$(XIAO_OTA_PAIR_ROLE_ID)-pair
XIAO_OTA_PAIR_APP_PACKAGE ?=
XIAO_OTA_PAIR_APP_CONTEXT ?=
XIAO_OTA_APP_FREEZE_DIR ?=
XIAO_OTA_APP_CONFIG ?= $(CURDIR)/platformio.ini
XIAO_OTA_APP_ENV = $(if $(strip $(ENV)),$(ENV),$(if $(filter sensecap_solar_p1,$(XIAO_OTA_PAIR_BOARD)),$(if $(filter 1,$(XIAO_OTA_PAIR_ROLE_ID)),SenseCap_Solar_repeater_ota_usb,SenseCap_Solar_companion_radio_ota_usb),$(if $(filter 1,$(XIAO_OTA_PAIR_ROLE_ID)),Xiao_nrf52_repeater_ota_usb,Xiao_nrf52_companion_radio_ota_usb)))
XIAO_OTA_TOOLS_TEST_PATTERN ?= test_*.py
XIAO_OTA_PAIR_PACKAGE_DIR ?= $(XIAO_OTA_PAIR_DIR)-packages
XIAO_OTA_PAIR_VERIFY_ONLY ?= 0
XIAO_OTA_USB_PORT ?=
XIAO_OTA_USB_PHASE ?=
XIAO_OTA_USB_BOOT_POLICY ?=
XIAO_OTA_USB_FRESH ?= 0
XIAO_OTA_NRFUTIL ?= $(HOME)/.platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py
XIAO_OTA_USB_PACKAGE = $(if $(filter compound,$(XIAO_OTA_USB_PHASE)),$(XIAO_OTA_PAIR_PACKAGE_DIR)/compound.zip,$(if $(filter bootloader,$(XIAO_OTA_USB_PHASE)),$(XIAO_OTA_PAIR_PACKAGE_DIR)/bootloader.zip,$(XIAO_OTA_PAIR_APP_PACKAGE)))
XIAO_OTA_VENDOR ?= $(TMPDIR)/Adafruit_nRF52_Bootloader_OTAFIX
XIAO_OTA_PRIVATE_KEY ?=
XIAO_OTA_IMAGE ?=
XIAO_OTA_ACTIVE_IMAGE ?=
XIAO_OTA_BOARD ?=
XIAO_OTA_COUNTER ?=
XIAO_OTA_ROLE_ID ?=
XIAO_OTA_TEST_BOARD_TARGET ?= XIAO_OTA_TARGET_XIAO_NRF52840
XIAO_OTA_TEST_ROLE_ID ?= $(if $(strip $(XIAO_OTA_ROLE_ID)),$(XIAO_OTA_ROLE_ID),0)
XIAO_OTA_UPSTREAM ?= $(XIAO_OTA_VENDOR)
OTA_NRF_REMOTE_BOOT_PROOF_PREFIX ?=
OTA_BUILD_DIR ?= $(TMPDIR)/ota-v4/build
OTA_IMAGE_FREEZE ?= $(TMPDIR)/ota-boot-builds/v4-solar-role1
OTA_ARM_PREFIX ?= $(HOME)/.platformio/packages/toolchain-gccarmnoneeabi/bin/arm-none-eabi-

.PHONY: build upload clean tmpdir test test-ota test-ota-host test-ota-native test-ota-disabled test-ota-queue-compatibility build-ota-targets build-ota-nrf52-targets build-ota-esp32-targets ota ota-device-inspect build-xiao-ota-bootloader-pair test-xiao-ota-bootloader-pair package-xiao-ota-bootloader-pair verify-xiao-ota-bootloader-pair-packages sign-xiao-ota-image test-xiao-ota-bootloader-tools test-xiao-ota-bootloader test-xiao-ota-boot-process test-nrf-unadmitted-boot-process test-ota-rf-to-boot

build: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)"
upload: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)" -t upload
clean: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)" -t clean
tmpdir:
	@mkdir -p "$(TMPDIR)"
test: tmpdir test-ota-host
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))
test-ota: test-ota-host test-ota-native test-ota-v4-platform test-ota-v4-esp test-ota-v4-boot test-ota-v4-decoder test-ota-disabled test-ota-queue-compatibility test-xiao-ota-bootloader
OTA_V4_DRIVER := $(TMPDIR)/ota-v4/receiver
.PHONY: build-ota-v4-driver test-ota-v4-e2e test-ota-v4-platform test-ota-v4-esp test-ota-v4-boot
build-ota-v4-driver: tmpdir
	@mkdir -p "$(TMPDIR)/ota-v4"
	$(CXX) -std=c++17 -O2 -Wall -Wextra -Wno-unused-function -I src \
	  scripts/tests/native/ota_v4_receiver.cpp src/helpers/ota/OtaV4Package.cpp \
	  src/helpers/ota/OtaV4Receiver.cpp src/helpers/ota/third_party/lzma/LzmaDec.c \
	  src/helpers/ota/third_party/lzma/Bra.c -o "$(OTA_V4_DRIVER)"
test-ota-host: build-ota-v4-driver
	OTA_V4_DRIVER="$(OTA_V4_DRIVER)" $(PYTHON) -m unittest discover -s scripts/tests -p 'test_*.py'
test-ota-v4-e2e: build-ota-v4-driver
	OTA_V4_DRIVER="$(OTA_V4_DRIVER)" $(PYTHON) -m unittest discover -s scripts/tests -p 'test_ota_deploy.py'
OTA_V4_IMAGE ?=
OTA_V4_IMAGE_EVIDENCE ?= $(TMPDIR)/ota-v4/image-evidence.json
.PHONY: test-ota-v4-image
test-ota-v4-image: build-ota-v4-driver
	@test -n "$(OTA_V4_IMAGE)" || { echo 'Select a genuine firmware image with OTA_V4_IMAGE.' >&2; exit 1; }
	OTA_V4_DRIVER="$(OTA_V4_DRIVER)" OTA_V4_IMAGE="$(OTA_V4_IMAGE)" OTA_V4_IMAGE_EVIDENCE="$(OTA_V4_IMAGE_EVIDENCE)" \
	  PYTHONPATH=scripts:scripts/tests $(PYTHON) -m unittest \
	  test_ota_deploy.NativeEndToEndTests.test_genuine_firmware_image_reaches_byte_exact_signed_confirmed_state
test-ota-v4-platform: tmpdir
	$(MAKE) --no-print-directory -f test/test_lora_ota_v4_platform/Makefile test
test-ota-v4-esp: tmpdir
	$(MAKE) --no-print-directory -f test/test_lora_ota_v4_esp/Makefile test
test-ota-v4-boot: tmpdir
	$(MAKE) --no-print-directory -f test/test_lora_ota_v4_boot/Makefile test
test-ota-native: tmpdir
	$(OTA_GTEST_ENV) $(PLATFORMIO) test -e native $(foreach filter,$(OTA_TEST_FILTER),-f '$(filter)')
.PHONY: test-ota-v4-native
test-ota-v4-native: tmpdir
	$(OTA_GTEST_ENV) $(PLATFORMIO) test -e native -f test_lora_ota_v4
.PHONY: test-ota-v4-decoder build-ota-solar ota-v4-arm-size
test-ota-v4-decoder: tmpdir
	@mkdir -p "$(TMPDIR)/ota-v4"
	$(CXX) -std=c++17 -Os -g -fsanitize=address,undefined -fno-omit-frame-pointer -I src \
	  scripts/tests/native/ota_compression_decoder_check.cpp src/helpers/ota/third_party/lzma/LzmaDec.c \
	  src/helpers/ota/third_party/lzma/Bra.c -o "$(TMPDIR)/ota-v4/decoder-check"
	ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$(TMPDIR)/ota-v4/decoder-check"
build-ota-solar: tmpdir
	PLATFORMIO_BUILD_DIR="$(OTA_BUILD_DIR)" $(MAKE) --no-print-directory build-xiao-ota-usb-app \
	  XIAO_OTA_PAIR_BOARD=sensecap_solar_p1 XIAO_OTA_PAIR_ROLE_ID=1 XIAO_OTA_APP_FREEZE_DIR="$(OTA_IMAGE_FREEZE)"
ota-v4-arm-size: tmpdir
	@mkdir -p "$(TMPDIR)/ota-v4"
	"$(OTA_ARM_PREFIX)g++" -std=c++17 -mcpu=cortex-m4 -mthumb -Os -fno-exceptions -fno-rtti \
	  -ffunction-sections -fdata-sections -fstack-usage -I src \
	  -c scripts/tests/native/ota_compression_size_probe.cpp -o "$(TMPDIR)/ota-v4/decoder-m4.o"
	"$(OTA_ARM_PREFIX)size" "$(TMPDIR)/ota-v4/decoder-m4.o" "$(OTA_IMAGE_FREEZE)/firmware.elf"
	"$(OTA_ARM_PREFIX)nm" -S -C --size-sort "$(TMPDIR)/ota-v4/decoder-m4.o" > "$(TMPDIR)/ota-v4/decoder-m4-symbols.txt"
	"$(OTA_ARM_PREFIX)nm" -S -C --size-sort "$(OTA_IMAGE_FREEZE)/firmware.elf" > "$(TMPDIR)/ota-v4/solar-m4-symbols.txt"
	@cat "$(TMPDIR)/ota-v4/decoder-m4.su"
# Real Mesh/Dispatcher/PacketManager behaviour with MESHCORE_LORA_OTA=0 (ordinary firmware is unchanged).
test-ota-disabled: tmpdir
	$(OTA_GTEST_ENV) $(PLATFORMIO) test -e native_lora_ota_disabled -f test_lora_ota_disabled
# The same fixture with OTA compiled in: queue reserve, priorities and ownership stay compatible.
test-ota-queue-compatibility: tmpdir
	$(OTA_GTEST_ENV) $(PLATFORMIO) test -e native_lora_ota_queue -f test_lora_ota_disabled
ESP32_OTA_IMAGE_ARGS ?=
.PHONY: test-ota-esp32-image
test-ota-esp32-image: tmpdir
	$(PYTHON) test/test_lora_ota_esp32/esp32_image_pipeline.py $(ESP32_OTA_IMAGE_ARGS)
OTA_LAYERS := protocol runtime storage trust integration esp32
.PHONY: test-ota-boot
test-ota-boot: test-xiao-ota-bootloader
.PHONY: $(addprefix test-ota-,$(OTA_LAYERS))
$(addprefix test-ota-,$(OTA_LAYERS)): test-ota-%: tmpdir
	$(OTA_GTEST_ENV) $(PLATFORMIO) test -e native -f 'test_lora_ota_$*'
build-ota-targets: tmpdir
	@set -e; for env in $(OTA_TARGET_ENVS); do $(PLATFORMIO) run -e "$$env"; done
build-ota-nrf52-targets:
	$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_NRF52_TARGET_ENVS)"
build-ota-esp32-targets:
	$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_ESP32_TARGET_ENVS)"

# Inspection never resets, configures, or infers OTA capability from USB IDs.
ota-device-inspect:
	$(PYTHON) scripts/ota_devices.py inspect --by-id "$(OTA_DEVICE_PORT)" --timeout "$(OTA_DEVICE_TIMEOUT)" $(if $(filter 1,$(OTA_DEVICE_DTR)),--dtr)
ota: tmpdir
	$(PYTHON) scripts/ota_uploader.py $(OTA_ARGS)

build-xiao-ota-bootloader-pair test-xiao-ota-bootloader-pair package-xiao-ota-bootloader-pair: tmpdir
	@test -n "$(XIAO_OTA_PAIR_BOARD)" && test -n "$(XIAO_OTA_PAIR_ROLE_ID)" || { echo 'Select XIAO_OTA_PAIR_BOARD and XIAO_OTA_PAIR_ROLE_ID.' >&2; exit 1; }
	$(MAKE) --no-print-directory -f bootloader/xiao_nrf52840_ota/Makefile $(if $(filter build-%,$@),pair,$(if $(filter test-%,$@),test,package-pair)) \
	  BOARD="$(XIAO_OTA_PAIR_BOARD)" ROLE="$(XIAO_OTA_PAIR_ROLE_ID)" OUTPUT="$(XIAO_OTA_PAIR_DIR)" VENDOR="$(XIAO_OTA_VENDOR)" \
	  APP_PACKAGE="$(XIAO_OTA_PAIR_APP_PACKAGE)" APP_CONTEXT="$(XIAO_OTA_PAIR_APP_CONTEXT)" PACKAGE_OUTPUT="$(XIAO_OTA_PAIR_PACKAGE_DIR)" VERIFY_ONLY="$(XIAO_OTA_PAIR_VERIFY_ONLY)"
verify-xiao-ota-bootloader-pair-packages: XIAO_OTA_PAIR_VERIFY_ONLY = 1
verify-xiao-ota-bootloader-pair-packages: package-xiao-ota-bootloader-pair
.PHONY: commission-xiao-ota-usb test-xiao-ota-usb-bench build-xiao-ota-usb-app
build-xiao-ota-usb-app: tmpdir
	@test -n "$(XIAO_OTA_PAIR_BOARD)" && test -n "$(XIAO_OTA_PAIR_ROLE_ID)" && test -n "$(XIAO_OTA_APP_FREEZE_DIR)" || { echo 'Select board, ROLE and a new APP freeze directory.' >&2; exit 1; }
	$(PYTHON) bootloader/xiao_nrf52840_ota/tools/record_app_context.py \
	  --config-input "$(XIAO_OTA_APP_CONFIG)" \
	  --config-output "$(XIAO_OTA_APP_FREEZE_DIR).ini" --environment "$(XIAO_OTA_APP_ENV)"
	XIAO_OTA_APP_BOARD="$(XIAO_OTA_PAIR_BOARD)" XIAO_OTA_APP_ROLE="$(XIAO_OTA_PAIR_ROLE_ID)" \
	  XIAO_OTA_APP_FREEZE="$(XIAO_OTA_APP_FREEZE_DIR)" \
	  $(PLATFORMIO) run -d "$(CURDIR)" -c "$(XIAO_OTA_APP_FREEZE_DIR).ini" \
	    -e "$(XIAO_OTA_APP_ENV)" -t xiao-app-context
# Exactly one explicitly selected phase, never endpoint discovery or an automatic three-write loop.
commission-xiao-ota-usb:
	@test "$(XIAO_OTA_USB_FRESH)" = 1 && test -n "$(XIAO_OTA_USB_PORT)" || { echo 'Select a physical USB bench port and explicitly authorize fresh commissioning.' >&2; exit 1; }
	$(PYTHON) bootloader/xiao_nrf52840_ota/tools/commission_pair.py \
	  --pair-manifest "$(XIAO_OTA_PAIR_DIR)/pair-manifest.json" \
	  --restore-package "$(XIAO_OTA_PAIR_APP_PACKAGE)" --package "$(XIAO_OTA_USB_PACKAGE)" \
	  --board "$(XIAO_OTA_PAIR_BOARD)" --role "$(XIAO_OTA_PAIR_ROLE_ID)" --app-context "$(XIAO_OTA_PAIR_APP_CONTEXT)" \
	  --usb-phase "$(XIAO_OTA_USB_PHASE)" --boot-policy "$(XIAO_OTA_USB_BOOT_POLICY)" \
	  --usb-port "$(XIAO_OTA_USB_PORT)" --fresh --nrfutil "$(XIAO_OTA_NRFUTIL)"
sign-xiao-ota-image: tmpdir
	@test -n "$(XIAO_OTA_ACTIVE_IMAGE)" && test -n "$(OTA_ARTIFACT_DIR)" || { echo 'Select the exact active APP and an output directory.' >&2; exit 1; }
	$(PYTHON) bootloader/xiao_nrf52840_ota/tools/sign_image.py --private-key "$(XIAO_OTA_PRIVATE_KEY)" \
	  --image "$(XIAO_OTA_IMAGE)" --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --counter "$(XIAO_OTA_COUNTER)" \
	  --active-image "$(XIAO_OTA_ACTIVE_IMAGE)" --output-dir "$(OTA_ARTIFACT_DIR)"
test-xiao-ota-bootloader-tools: tmpdir
	$(PYTHON) -m unittest discover -s bootloader/xiao_nrf52840_ota/tests -p '$(XIAO_OTA_TOOLS_TEST_PATTERN)'

XIAO_OTA_BOOT_PROCESS_SOURCES = \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_io.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_sha256.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	bootloader/xiao_nrf52840_ota/tests/crc16_host.c \
	bootloader/xiao_nrf52840_ota/tests/fake_io.c
XIAO_OTA_BOOT_PROCESS_CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror \
	-Ibootloader/xiao_nrf52840_ota/include \
	-Ibootloader/xiao_nrf52840_ota/src \
	-Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	-Ibootloader/xiao_nrf52840_ota/tests \
	-Isrc/ota/trust/third_party/ed25519 \
	-DXIAO_OTA_BOARD_TARGET="$(XIAO_OTA_TEST_BOARD_TARGET)" \
	-DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	-Wno-unused-function -Wno-sign-compare -Wno-shadow \
	-Wno-unterminated-string-initialization
OTA_RADIO_FAULT_GTEST ?= .pio/libdeps/native/googletest/googletest
.PHONY: test-ota-radio-fault-attribution
## Narrow source-only product gate; uses the existing native GTest dependency, never PlatformIO/SDKs.
test-ota-radio-fault-attribution: tmpdir
	@mkdir -p "$(TMPDIR)/ota-radio-fault-attribution"
	$(CXX) -std=c++17 -pthread -DMESHCORE_LORA_OTA=1 -I src -I test/mocks \
	  -I "$(OTA_RADIO_FAULT_GTEST)/include" -I "$(OTA_RADIO_FAULT_GTEST)" \
	  test/test_lora_ota_integration/test_radio_fault_attribution.cpp \
	  "$(OTA_RADIO_FAULT_GTEST)/src/gtest-all.cc" "$(OTA_RADIO_FAULT_GTEST)/src/gtest_main.cc" \
	  -o "$(TMPDIR)/ota-radio-fault-attribution/product-test"
	"$(TMPDIR)/ota-radio-fault-attribution/product-test"

.PHONY: test-ota-radio-tx-completion
## Native real Dispatcher/wrapper completion service plus unchanged strict fault gate.
test-ota-radio-tx-completion: tmpdir
	@mkdir -p "$(TMPDIR)/ota-radio-tx-completion"
	$(CXX) -std=c++17 -pthread -ffunction-sections -fdata-sections -Wl,--gc-sections \
	  -DMESHCORE_LORA_OTA=1 -DMESHCORE_RADIO_TX_COMPLETION_NATIVE=1 \
	  -DLORA_SF=7 -DLORA_FREQ=907.525 -DLORA_BW=250 -DLORA_CR=5 -DLORA_TX_POWER=2 \
	  -I test/test_lora_ota_integration/radio_tx_mocks -I src -I test/mocks \
	  -I "$(OTA_RADIO_FAULT_GTEST)/include" -I "$(OTA_RADIO_FAULT_GTEST)" \
	  src/Dispatcher.cpp src/Packet.cpp src/helpers/radiolib/RadioLibWrappers.cpp \
	  test/test_lora_ota_integration/test_radio_fault_attribution.cpp \
	  test/test_lora_ota_integration/test_radio_tx_completion.cpp \
	  "$(OTA_RADIO_FAULT_GTEST)/src/gtest-all.cc" "$(OTA_RADIO_FAULT_GTEST)/src/gtest_main.cc" \
	  -o "$(TMPDIR)/ota-radio-tx-completion/product-test"
	"$(TMPDIR)/ota-radio-tx-completion/product-test"

test-xiao-ota-boot-process: tmpdir
	@mkdir -p "$(TMPDIR)/xiao-ota-host"
	$(CC) $(XIAO_OTA_BOOT_PROCESS_CFLAGS) \
	  $(XIAO_OTA_BOOT_PROCESS_SOURCES) \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_process.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_process"
	"$(TMPDIR)/xiao-ota-host/test_boot_process"

test-xiao-ota-usb-bench: tmpdir
	@mkdir -p "$(TMPDIR)/xiao-usb-bench"
	$(CC) $(XIAO_OTA_BOOT_PROCESS_CFLAGS) $(XIAO_OTA_BOOT_PROCESS_SOURCES) \
	  bootloader/xiao_nrf52840_ota/tests/test_usb_bench_reset.c \
	  -o "$(TMPDIR)/xiao-usb-bench/reset"
	"$(TMPDIR)/xiao-usb-bench/reset"
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -fno-pie -no-pie \
	  -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast \
	  -Ibootloader/xiao_nrf52840_ota/tests/qspi_mock \
	  -I"$(XIAO_OTA_VENDOR)/lib/nrfx/mdk" \
	  -Ibootloader/xiao_nrf52840_ota/include -Ibootloader/xiao_nrf52840_ota/src \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_boot.c \
	  bootloader/xiao_nrf52840_ota/tests/test_qspi_adapter.c \
	  -o "$(TMPDIR)/xiao-usb-bench/watchdog"
	"$(TMPDIR)/xiao-usb-bench/watchdog"
test-nrf-unadmitted-boot-process: tmpdir
	@mkdir -p "$(TMPDIR)/rf-n1-boot-host"
	$(CC) $(XIAO_OTA_BOOT_PROCESS_CFLAGS) \
	  -DOTA_NRF_UNADMITTED_BOOT_PROCESS_TEST \
	  $(XIAO_OTA_BOOT_PROCESS_SOURCES) \
	  test/test_lora_ota_integration/test_nrf_unadmitted_boot_process.c \
	  -o "$(TMPDIR)/rf-n1-boot-host/test_nrf_unadmitted_boot_process"
	"$(TMPDIR)/rf-n1-boot-host/test_nrf_unadmitted_boot_process" $(if $(OTA_NRF_REMOTE_BOOT_PROOF_PREFIX),"$(OTA_NRF_REMOTE_BOOT_PROOF_PREFIX)")

test-ota-rf-to-boot: test-ota-v4-boot

test-xiao-ota-bootloader: tmpdir test-xiao-ota-bootloader-tools test-xiao-ota-boot-process
	@mkdir -p "$(TMPDIR)/xiao-ota-host"
	$(CC) -std=c11 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_sha256.c \
	  bootloader/xiao_nrf52840_ota/tests/test_record.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_record"
	"$(TMPDIR)/xiao-ota-host/test_record"
	$(CC) -std=c11 -O2 -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/tests/test_ed25519.c \
	  -Wno-unused-function -Wno-sign-compare -Wno-shadow \
	  -Wno-unterminated-string-initialization \
	  -Wl,--gc-sections \
	  -o "$(TMPDIR)/xiao-ota-host/test_ed25519"
	"$(TMPDIR)/xiao-ota-host/test_ed25519"
	$(CC) -std=c11 -O2 -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/tests/test_descriptor_contract.c \
	  -Wno-unused-function -Wno-sign-compare -Wno-shadow \
	  -Wno-unterminated-string-initialization \
	  -Wl,--gc-sections \
	  -o "$(TMPDIR)/xiao-ota-host/test_descriptor_contract"
	"$(TMPDIR)/xiao-ota-host/test_descriptor_contract"
	$(CC) -std=c11 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_info.c \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_info.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_info"
	"$(TMPDIR)/xiao-ota-host/test_boot_info"
	python3 bootloader/xiao_nrf52840_ota/tests/test_source.py
