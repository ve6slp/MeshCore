ENTRY(stage_entry)
MEMORY {
  FLASH (rx) : ORIGIN = 0xC4000, LENGTH = 0x10000
  RAM (rwx) : ORIGIN = 0x20020000, LENGTH = 0x10000
}
SECTIONS {
  .pair_header : { KEEP(*(.pair_header)) } > FLASH
  .text 0xC4040 : { KEEP(*(.text.stage_entry)) *(.text*) *(.rodata*) } > FLASH
  .ARM.extab : { *(.ARM.extab*) } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH
  .data : {
    __data_start__ = .;
    *(.data*)
    . = ALIGN(4);
    __data_end__ = .;
  } > RAM AT > FLASH
  __data_load__ = LOADADDR(.data);
  .bss (NOLOAD) : {
    __bss_start__ = .;
    *(.bss*) *(COMMON)
    . = ALIGN(4);
    __bss_end__ = .;
  } > RAM
  /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.pair_header) == 36, "paired header ABI changed")
ASSERT(LOADADDR(.data) + SIZEOF(.data) <= 0xD4000, "stage2 initialized load overflow")
ASSERT(__bss_end__ <= 0x20030000, "stage2 runtime overflow")
