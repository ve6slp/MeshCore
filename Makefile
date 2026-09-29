PLATFORMIO ?= pio

# Keep build/test scratch inside the repo. The system /tmp is a small
# memory-backed tmpfs and cannot hold toolchain intermediates.
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

NATIVE_TEST_ENVS ?= native native_kiss_modem

OTA_TEST_FILTER ?= test_lora_ota_*
OTA_TARGET_ENVS ?= SenseCap_Solar_companion_radio_usb Xiao_S3_WIO_companion_radio_usb

# Representative non-OTA targets, used to prove the OTA build-filter and
# platformio.ini changes did not regress platforms that never enable OTA.
NON_OTA_TARGET_ENVS ?= Heltec_v3_repeater RAK_4631_repeater

.PHONY: tmpdir test test-ota test-ota-protocol test-ota-runtime test-ota-storage \
        test-ota-trust test-ota-boot test-ota-integration clean-ota-targets \
        build-ota-targets build-ota-baseline-targets build-non-ota-targets \
        verify-ota-software clean-tmp

tmpdir:
	@mkdir -p $(TMPDIR)

## Full native unit-test suite (pre-existing tests plus OTA).
test: tmpdir
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))

## All OTA native tests.
test-ota: tmpdir
	$(PLATFORMIO) test -e native -f '$(OTA_TEST_FILTER)'

## Per-layer OTA tests, for fast iteration on a single scope.
test-ota-protocol: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_protocol'

test-ota-runtime: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_runtime'

test-ota-storage: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_storage'

test-ota-trust: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_trust'

test-ota-boot: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_boot'

test-ota-integration: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_integration'

## Compile the OTA-capable firmware targets.
build-ota-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> building $$env"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## Compile the same firmware targets with OTA disabled for size comparison.
build-ota-baseline-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> baseline building $$env"; \
	  PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA=0' $(PLATFORMIO) run -e $$env || exit 1; \
	done

clean-ota-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> cleaning $$env"; \
	  $(PLATFORMIO) run -e $$env -t clean || exit 1; \
	done

## Regression guard: platforms that never enable OTA must still build.
build-non-ota-targets: tmpdir
	@for env in $(NON_OTA_TARGET_ENVS); do \
	  echo "==> building $$env (OTA disabled)"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## Software-level qualification only.
## Passing this gate means the native tests pass and the OTA-enabled and
## non-OTA firmware targets link. It does NOT mean a device can be updated:
## on-device radio behaviour, real flash writes, the custom nRF52840
## QSPI-aware bootloader, trusted boot, the anti-rollback counter backend and
## power-loss rollback all remain hardware acceptance gates.
verify-ota-software: test build-ota-targets build-non-ota-targets
	@echo
	@echo "OTA software checks passed: native tests green, firmware targets link."
	@echo "NOT qualified here: on-device radio, flash, bootloader, anti-rollback, rollback."

clean-tmp:
	rm -rf $(TMPDIR)
