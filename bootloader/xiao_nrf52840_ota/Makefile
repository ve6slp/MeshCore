ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
PRODUCT := $(ROOT)/bootloader/xiao_nrf52840_ota
BOARD ?= xiao_nrf52840_sense
CLIENT41 ?= 0
ROLE ?= $(if $(filter 1,$(CLIENT41)),0,1)
OUTPUT ?= $(ROOT)/.tmp/ota-boot-builds/$(BOARD)-role$(ROLE)-pair
VENDOR ?= $(ROOT)/.tmp/otafix-stage2-prototype/vendor
PROVENANCE ?= $(ROOT)/.tmp/otafix-stage2-prototype/vendor-provenance.json
APP_PACKAGE ?= $(if $(filter 1,$(CLIENT41)),$(ROOT)/.tmp/live-app-contract/companion41-uf2-01/app-build/Xiao_nrf52_companion_radio_usb/firmware.zip,$(ROOT)/.tmp/ota-index/04705d6ac8bef3039273e97311e6cea1457e766a/pio-build/Xiao_nrf52_repeater_ota_usb/firmware.zip)
PACKAGE_OUTPUT ?= $(ROOT)/.tmp/ota-boot-builds/$(if $(filter 1,$(CLIENT41)),sense-role0-client41,sense-role1)-packages
NRFUTIL ?= $(HOME)/.platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py
VERIFY_ONLY ?= 0
export SOURCE_DATE_EPOCH ?= 1779344629
export TMPDIR := $(OUTPUT)/scratch
export TMP := $(TMPDIR)
export TEMP := $(TMPDIR)
export PYTHONDONTWRITEBYTECODE := 1
.PHONY: pair test package-pair
pair:
	@mkdir -p "$(TMPDIR)"
	python3 "$(PRODUCT)/tools/build_pair.py" --board "$(BOARD)" --role "$(ROLE)" \
	  --output "$(OUTPUT)" --vendor "$(VENDOR)" --provenance "$(PROVENANCE)"
test:
	@mkdir -p "$(TMPDIR)" "$(OUTPUT)/scratch"
	python3 "$(PRODUCT)/tools/build_pair.py" --test --board "$(BOARD)" --role "$(ROLE)" \
	  --output "$(OUTPUT)" --vendor "$(VENDOR)" --provenance "$(PROVENANCE)"
	XIAO_TEST_PAIR_DIR="$(OUTPUT)" XIAO_TEST_APP_PACKAGE="$(APP_PACKAGE)" XIAO_TEST_CLIENT41="$(CLIENT41)" \
	  XIAO_TEST_NRFUTIL="$(NRFUTIL)" python3 "$(PRODUCT)/tests/test_package_pair.py"
package-pair:
	python3 "$(PRODUCT)/tools/package_pair.py" --pair "$(OUTPUT)" \
	  --app-package "$(APP_PACKAGE)" --output "$(PACKAGE_OUTPUT)" --nrfutil "$(NRFUTIL)" \
	  $(if $(filter 1,$(VERIFY_ONLY)),--verify-only) $(if $(filter 1,$(CLIENT41)),--client41)
