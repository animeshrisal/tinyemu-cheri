OUTPUT_ARCH("riscv")
ENTRY(_entry)

CAP_ALIGN = 0x20;

PHDRS {
  text PT_LOAD FLAGS(5); /* R + X */
  rodata PT_LOAD FLAGS(4); /* R */
  data PT_LOAD FLAGS(6); /* R + W */
}

SECTIONS {
  /* Start at QEMU entry point */
  . = 0x80000000;

  /* Text section (executable code) */
  .text : {
    *(.text .text.*)
    . = ALIGN(0x1000);
    PROVIDE(etext = .);
  } :text

  /* Place unwind sections after text */
  .eh_frame_hdr : {
    *(.eh_frame_hdr)
  } :text

  .eh_frame : {
    *(.eh_frame)
  } :text

  /* Read-only data */
  .rodata : {
    . = ALIGN(CAP_ALIGN);
    *(.srodata .srodata.*)
    *(.rodata .rodata.*)
  } :rodata

  /* Capability relocation data */
  . = ALIGN(CAP_ALIGN);
  __cap_relocs : {
    *(__cap_relocs __cap_relocs.*)
  } :data


  /* Capability table - MUST come before .data */
  .captable : {
    . = ALIGN(CAP_ALIGN);
    *(.captable)
  } :data
  
  /* Initialized data */
  .data : {
    . = ALIGN(CAP_ALIGN);
    *(.sdata .sdata.*)
    *(.data .data.*)
  } :data

  /* Uninitialized data (BSS) */
  .bss ALIGN(CAP_ALIGN): {
    *(.bss)
  } : data

  __start_bss = ADDR(.bss);
  __stop_bss = ALIGN(__start_bss + SIZEOF(.bss), CAP_ALIGN);
  __bss_size = __stop_bss - __start_bss;
    
  /* Stack space */
  .stack (NOLOAD) : {
    . = ALIGN(CAP_ALIGN);
    stack0 = .;
    . += 4096;
  }



  PROVIDE(end = .);
}
