set -xue

# QEMU for CHERI-RISC-V64 (this comes from cheribuild's QEMU)
QEMU=qemu-system-riscv64cheri

# Compiler wrapper (ccc will expand to clang with CHERI flags)
CC="/home/cheri/cheri/output/sdk/bin/clang --target=riscv64-unknown-freebsd -mabi=l64pc128d -march=rv64gxcheri -nostdlib \
         -Wall -Werror -Wcheri -g -O2 \
         --sysroot=/home/cheri/cheri/output/sdk/sysroot-riscv64-purecap"



# Source files
ENTRY=entry.S
MAIN=main.c
LINKER=linker.ld

# Compile sources
$CC -c $ENTRY -o entry.o
$CC -c $MAIN -o main.o

# Link the kernel ELF using the CHERI-aware toolchain
$CHERI_CLANG \
  -nostdlib -nostartfiles -ffreestanding -static \
  -Wl,-T,$LINKER \
  -Wl,-Map=kernel.map \
  entry.o main.o\
  -o kernel.elf

# $QEMU -machine virt -bios ./opensbi-riscv32-generic-fw_dynamic.bin -nographic -serial mon:stdio --no-reboot -kernel kernel.elf
$QEMU -bios none -kernel kernel.elf -nographic -M virt  -d nochain,cpu -S -s
