.syntax unified
.cpu cortex-m4
.thumb
.section .text.stage_entry,"ax",%progbits
.global stage_entry
.type stage_entry,%function
.thumb_func
stage_entry:
  /* AAPCS returning service; primary MSP has a separately reserved 64KiB
     service-call stack margin. No interrupt/vector/SoftDevice handoff. */
  b stage_run
.size stage_entry, .-stage_entry
