/* 66 KiB authenticated OTA bootloader. InternalFS 0xED000..0xF4000 is consumed. */
SEARCH_DIR(.)

MEMORY
{
  FLASH (rx) : ORIGIN = 0xED000, LENGTH = 0xFD800-0xED000
  BOOTLOADER_CONFIG (r): ORIGIN = 0xFD800, LENGTH = 2K
  MBR_PARAMS_PAGE (rw) : ORIGIN = 0xFE000, LENGTH = 0x1000
  BOOTLOADER_SETTINGS (rw) : ORIGIN = 0xFF000, LENGTH = 0x1000
  RAM (rwx) : ORIGIN = 0x20008000, LENGTH = 0x20040000-0x20008000
  DBL_RESET (rwx) : ORIGIN = 0x20007F7C, LENGTH = 0x04
  NOINIT (rwx) : ORIGIN = 0x20007F80, LENGTH = 0x80
  UICR_BOOTLOADER (r) : ORIGIN = 0x10001014, LENGTH = 0x04
  UICR_MBR_PARAM_PAGE(r) : ORIGIN = 0x10001018, LENGTH = 0x04
}

SECTIONS
{
  .fs_data_out ALIGN(4):
  {
    PROVIDE(__start_fs_data = .);
    KEEP(*(fs_data))
    PROVIDE(__stop_fs_data = .);
  } = 0
  .bootloaderConfig : { KEEP(*(.bootloaderConfig)) } > BOOTLOADER_CONFIG
  .bootloaderSettings(NOLOAD) : { } > BOOTLOADER_SETTINGS
  .uicrBootStartAddress : { KEEP(*(.uicrBootStartAddress)) } > UICR_BOOTLOADER
  .mbrParamsPage(NOLOAD) : { } > MBR_PARAMS_PAGE
  .uicrMbrParamsPageAddress : { KEEP(*(.uicrMbrParamsPageAddress)) } > UICR_MBR_PARAM_PAGE
  .dbl_reset(NOLOAD) : { } > DBL_RESET
  .noinit(NOLOAD) : { } > NOINIT
}

INCLUDE "nrf_common.ld"

