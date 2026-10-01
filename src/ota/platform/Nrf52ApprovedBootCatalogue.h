// GENERATED FILE -- DO NOT EDIT BY HAND.
// Produced by scripts/ota_boot_catalogue.py from pinned PUBLIC artifacts only.
// schema_version=2
// source_date_epoch=1779344629
// board=xiao_nrf52840_ble
// toolchain=arm-none-eabi-gcc (15:14.2.rel1-1) 14.2.1 20241119
// out_name=xiao_nrf52840_ble_bootloader-0.11.0
// submodule_pin[Adafruit_nRF52_Bootloader]=c67f0bcf0fa8e841426335b1bbde91cda6ca1f50
// submodule_pin[nrfx]=7a4c9d946cf1801771fc180acdbf7b878f270093
// submodule_pin[tinycrypt]=cf24c907a61c01bc2c4e1ee0ae24457c27a840a2
// submodule_pin[tinyusb]=9775e76910d569ec73b8dd946f3fa5fe5414acdb
// submodule_pin[uf2]=b19ac9ad613e11a062e4d00845e2b80e6b0ad29f
// build_option=BOARD=xiao_nrf52840_ble
// build_option=SOURCE_DATE_EPOCH=1779344629
// build_option=CFLAGS=-DNRF52840_XXAA -DS140 -mthumb -mabi=aapcs -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -ggdb -Os -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -fstack-usage -fno-strict-aliasing -Wall -Wextra -Werror -Wfatal-errors -Werror-implicit-function-declaration -Wfloat-equal -Wundef -Wshadow -Wwrite-strings -Wsign-compare -Wmissing-format-attribute -Wno-endif-labels -Wunreachable-code -Wno-unused-parameter -Wno-expansion-to-defined -fno-ipa-modref -D__HEAP_SIZE=0 -DCONFIG_GPIO_AS_PINRESET -DCONFIG_NFCT_PINS_AS_GPIOS -DSOFTDEVICE_PRESENT -DUF2_VERSION="0.11.0" -DBLEDIS_FW_VERSION="0.11.0 s140 7.3.0" -DMK_BOOTLOADER_VERSION=(((0<<16)|(11<<8)|(0))) -DDFU_APP_DATA_RESERVED=10*4096
// build_option=ASFLAGS=-DNRF52840_XXAA -DS140 -mthumb -mabi=aapcs -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -ggdb -Os -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -fstack-usage -fno-strict-aliasing -Wall -Wextra -Werror -Wfatal-errors -Werror-implicit-function-declaration -Wfloat-equal -Wundef -Wshadow -Wwrite-strings -Wsign-compare -Wmissing-format-attribute -Wno-endif-labels -Wunreachable-code -Wno-unused-parameter -Wno-expansion-to-defined -fno-ipa-modref -D__HEAP_SIZE=0 -DCONFIG_GPIO_AS_PINRESET -DCONFIG_NFCT_PINS_AS_GPIOS -DSOFTDEVICE_PRESENT -DUF2_VERSION="0.11.0" -DBLEDIS_FW_VERSION="0.11.0 s140 7.3.0" -DMK_BOOTLOADER_VERSION=(((0<<16)|(11<<8)|(0))) -DDFU_APP_DATA_RESERVED=10*4096
// build_option=INC_PATHS=-Isrc -Isrc/boards -Isrc/boards/xiao_nrf52840_ble -Isrc/cmsis/include -Isrc/usb -Ilib/tinyusb/src -Ilib/nrfx -Ilib/nrfx/mdk -Ilib/nrfx/hal -Ilib/nrfx/drivers/include -Ilib/nrfx/drivers/src -Ilib/sdk11/components/libraries/bootloader_dfu/hci_transport -Ilib/sdk11/components/libraries/bootloader_dfu -Ilib/sdk11/components/drivers_nrf/pstorage -Ilib/sdk11/components/ble/common -Ilib/sdk11/components/ble/ble_services/ble_dfu -Ilib/sdk11/components/ble/ble_services/ble_dis -Ilib/sdk/components/libraries/timer -Ilib/sdk/components/libraries/scheduler -Ilib/sdk/components/libraries/crc16 -Ilib/sdk/components/libraries/util -Ilib/sdk/components/libraries/hci/config -Ilib/sdk/components/libraries/uart -Ilib/sdk/components/libraries/hci -Ilib/sdk/components/drivers_nrf/delay -Ilib/softdevice/s140_nrf52_7.3.0/s140_nrf52_7.3.0_API/include -Ilib/softdevice/s140_nrf52_7.3.0/s140_nrf52_7.3.0_API/include/nrf52
// build_option=LDFLAGS=-DNRF52840_XXAA -DS140 -mthumb -mabi=aapcs -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -ggdb -Os -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -fstack-usage -fno-strict-aliasing -Wall -Wextra -Werror -Wfatal-errors -Werror-implicit-function-declaration -Wfloat-equal -Wundef -Wshadow -Wwrite-strings -Wsign-compare -Wmissing-format-attribute -Wno-endif-labels -Wunreachable-code -Wno-unused-parameter -Wno-expansion-to-defined -fno-ipa-modref -D__HEAP_SIZE=0 -DCONFIG_GPIO_AS_PINRESET -DCONFIG_NFCT_PINS_AS_GPIOS -DSOFTDEVICE_PRESENT -DUF2_VERSION="0.11.0" -DBLEDIS_FW_VERSION="0.11.0 s140 7.3.0" -DMK_BOOTLOADER_VERSION=(((0<<16)|(11<<8)|(0))) -DDFU_APP_DATA_RESERVED=10*4096 -Wl,-L,linker -Wl,-T,linker/nrf52840.ld -Wl,--print-memory-usage -Wl,-Map=_build/build-xiao_nrf52840_ble/xiao_nrf52840_ble_bootloader-0.11.0.out.map -Wl,-cref -Wl,-gc-sections -specs=nosys.specs -specs=nano.specs
// artifact_sha256[mbr_hex]=11908ba24b2826c1470d3da7ffa518932ac44ed6fd6caccfa93437426030c8a8
// artifact_sha256[softdevice_hex]=5f460d35efcb4ab0f280e83cd15f804e979172a3646c5b66e86af6b7b2975ba6
// artifact_sha256[stock_elf]=dd7a0aa5e361a11a39f314bf116ce39390ce5883fe0669ff68fbe1dbbd170ba1
// artifact_sha256[stock_hex]=09174fa19d14666fbd2ab710c8fd86ef2b812c4e05d8acb78b849fd7adb3783f
#pragma once

#include "Nrf52BootCatalogue.h"

static_assert(::ota::platform::kNrf52BootCatalogueSchemaVersion == 2u,
              "generated Nrf52ApprovedBootCatalogue.h schema version does not match the DTO header; regenerate via scripts/ota_boot_catalogue.py");

namespace ota {
namespace platform {

inline constexpr Nrf52ApprovedBootRow kApprovedBootCatalogueRows[] = {
  {
    /* target_id */ 0x584e3430,
    /* profile_id */ 1,
    /* loader_kind */ ::ota::platform::Nrf52LoaderKind::VendorStock,
    /* role_binding */ ::ota::platform::Nrf52RoleBinding::NotApplicable,
    /* expected_role_id */ ::ota::platform::kNrf52BootFieldUnset,
    /* expected_boot_info */ {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    /* stock_code_sha256 */ {0x2D, 0xCD, 0x34, 0x63, 0x30, 0x6A, 0xD2, 0x82, 0x9E, 0x0F, 0x2C, 0x2C, 0x21, 0x83, 0x22, 0xC6, 0x14, 0x8D, 0xB0, 0xBC, 0x29, 0xAC, 0x59, 0x2B, 0x0F, 0xD9, 0xD0, 0xD0, 0xC3, 0x21, 0xE0, 0x5F},
    /* cf2_sha256 */ {0x0A, 0xE7, 0x71, 0xD0, 0x16, 0xA0, 0x1A, 0x5C, 0x76, 0x4E, 0x9C, 0x4F, 0x17, 0x59, 0xD7, 0xAC, 0x83, 0x9B, 0x2E, 0x81, 0xE0, 0xB2, 0xB6, 0xC0, 0x76, 0x1C, 0x85, 0xD2, 0x1E, 0x25, 0xB0, 0xBC},
    /* mbr_sha256 */ {0xF4, 0x28, 0xCE, 0xE0, 0x0E, 0xCE, 0x4D, 0x83, 0x23, 0xB9, 0xBC, 0x07, 0xB1, 0xBE, 0x88, 0x8B, 0x20, 0x9F, 0xCF, 0xA1, 0xC6, 0x0C, 0xA1, 0x5F, 0x83, 0x34, 0x19, 0xDF, 0xB7, 0x78, 0x58, 0x49},
    /* softdevice_sha256 */ {0x52, 0x10, 0x2C, 0x1F, 0x53, 0x00, 0x69, 0x39, 0x54, 0x31, 0xDA, 0xB6, 0x26, 0xCF, 0x61, 0x83, 0x10, 0xDD, 0x54, 0xCE, 0x57, 0x9B, 0x8B, 0xF2, 0x5A, 0xBA, 0x19, 0x08, 0x52, 0x6A, 0xFD, 0x0B},
    /* mbr_vectors */ {0x20000400, 0x00000a81},
    /* softdevice_vectors */ {0x200013c8, 0x00025e39},
    /* loader_vectors */ {0x20040000, 0x000fb555},
    /* ficr_geometry */ {0x00001000, 0x00000100},
    /* softdevice_info_magic */ 0x51b1e5db,
    /* softdevice_info_size */ 0x00027000,
    /* softdevice_fwid */ 0x0123,
    /* softdevice_variant */ 140,
    /* softdevice_version */ 7003000,
    /* softdevice_unique_id */ {0x7A, 0x2E, 0x9A, 0xC6, 0x7D, 0xB6, 0x6C, 0xFA, 0xF3, 0x57, 0x21, 0xCC, 0xC3, 0x10, 0xD5, 0xE5, 0x14, 0x71, 0xFB, 0x3C},
  },
};
inline constexpr size_t kApprovedBootCatalogueRowCount = sizeof(kApprovedBootCatalogueRows) / sizeof(kApprovedBootCatalogueRows[0]);

}  // namespace platform
}  // namespace ota
