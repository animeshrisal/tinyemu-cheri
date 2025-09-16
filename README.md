# TinyEMU with cheri extensions

[![Build](https://github.com/fernandotcl/TinyEMU/workflows/Build/badge.svg)][GitHub Actions]

This is a modified version of [Fabrice Bellard's TinyEMU][TinyEMU].

[GitHub Actions]: https://github.com/fernandotcl/TinyEMU/actions?query=workflow%3ABuild
[TinyEMU]: https://bellard.org/tinyemu/

## Credits

TinyEMU was created by [Fabrice Bellard][fabrice]. Forked from [Fernando Tarlá Cardoso Lemos][fernando].

[fabrice]: https://bellard.org
[fernando]: mailto:fernandotcl@gmail.com

## License

Unless otherwise specified in individual files, TinyEMU is available under the MIT license.

The SLIRP library has its own license (two-clause BSD license).


## CHERI
This emulator has been modified to include CHERI capabilities

It is currently a work in progress. This section is to document the changes.


### Things done
1. Write most of the opcodes. There is a single line comment for each implemented opcode for easier search.
2. A cheri.c and cheri.h file have been included that performs specific cheri operations.
3. Write and read capabilities from memory. At the moment, the capabilities are stored in a table
4. Added some cheri state to `RiscVCPUState` struct in `riscv_cpu_priv.h` 
5. The riscv_cpu_template.h has been modified to run cheri instructions.
6. A table has been created to hold the cheri instructions
7. The cheri code was writtem for 64-bit systems.
8. The project includes a `kernel.elf` that was used for testing and a `uncompressed.txt` file that shows the cheri assembly code
9. There is a test folder that contains the original c code. The test prints a hello world using the uart and then tries to access out of bound memory.


### Things to do
1. Some code needs to be writte for some function. All of them are commented with 
`TODO`
2. Fix `mret`. When mret is executed, the code loop is finished and returns to the previous function. But the program crashes when returning to the previous function.
3. Read the capability data from elf file instead of being hardcoded.

### How to run
`make`
`./temu test.cfg`

