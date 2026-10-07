ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
PRODUCT := $(ROOT)/bootloader/xiao_nrf52840_ota
PYTHON ?= python3
BOARD ?=
ROLE ?=
OUTPUT ?= $(ROOT)/.tmp/ota-boot-builds/$(BOARD)-role$(ROLE)-pair
VENDOR ?= $(ROOT)/.tmp/Adafruit_nRF52_Bootloader_OTAFIX
VENDOR_URL ?= https://github.com/oltaco/Adafruit_nRF52_Bootloader_OTAFIX.git
VENDOR_PIN := a62825be4733f500271c89b5ec489fd609748e97
APP_PACKAGE ?=
PACKAGE_OUTPUT ?= $(OUTPUT)-packages
NRFUTIL ?= $(HOME)/.platformio/packages/tool-adafruit-nrfutil/adafruit-nrfutil.py
VERIFY_ONLY ?= 0
export SOURCE_DATE_EPOCH ?= $(shell git -C "$(VENDOR)" show -s --format=%ct "$(VENDOR_PIN)" 2>/dev/null)
export TMPDIR := $(OUTPUT)/scratch
export TMP := $(TMPDIR)
export TEMP := $(TMPDIR)
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: fetch pair test package-pair
fetch:
	@test ! -e "$(VENDOR)" || { echo 'Vendor path exists; refusing to overwrite.' >&2; exit 1; }
	@mkdir -p "$(TMPDIR)"
	git clone --quiet --config core.hooksPath=/dev/null "$(VENDOR_URL)" "$(VENDOR)"
	git -C "$(VENDOR)" checkout --quiet --detach "$(VENDOR_PIN)"
	git -C "$(VENDOR)" submodule update --quiet --init --depth 1
pair:
	@mkdir -p "$(TMPDIR)"
	$(PYTHON) "$(PRODUCT)/tools/build_pair.py" \
	  --board "$(BOARD)" --role "$(ROLE)" --output "$(OUTPUT)" --vendor "$(VENDOR)"
test:
	@mkdir -p "$(TMPDIR)"
	$(PYTHON) "$(PRODUCT)/tools/build_pair.py" --test \
	  --board "$(BOARD)" --role "$(ROLE)" --output "$(OUTPUT)" --vendor "$(VENDOR)"
	XIAO_TEST_PAIR_DIR="$(OUTPUT)" XIAO_TEST_APP_PACKAGE="$(APP_PACKAGE)" \
	  XIAO_TEST_NRFUTIL="$(NRFUTIL)" $(PYTHON) -m unittest discover -s "$(PRODUCT)/tests" -p test_package_pair.py
package-pair:
	$(PYTHON) "$(PRODUCT)/tools/package_pair.py" --pair "$(OUTPUT)" \
	  --board "$(BOARD)" --role "$(ROLE)" --app-package "$(APP_PACKAGE)" \
	  --output "$(PACKAGE_OUTPUT)" --nrfutil "$(NRFUTIL)" $(if $(filter 1,$(VERIFY_ONLY)),--verify-only)
