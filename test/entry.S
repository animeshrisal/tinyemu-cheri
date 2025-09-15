.section .text
.global _entry
.extern __start_bss
.extern __stop_bss

_entry:
    # --- Clear EXEC permission on DDC (W^X policy) ---
    cspecialr ct1, ddc


    li t2, 0x7ffffffd
    candperm  ct1, ct1, t2
    cspecialw ddc, ct1

    # --- Get stack pointer capability ---
1:
    auipcc    ca0, %pcrel_hi(next)
    cincoffset ca0, ca0, %pcrel_lo(1b)

    cspecialr ct3, pcc
    csetaddr  ca0, ct3, a0

    li	      t5, 0x7FFFFFD7
    candperm  ca0, ca0, t5

    li        t3, 1
    csetflags ca0, ca0, t3
    jr.cap    ca0

next:
    auipcc    ca0, %pcrel_hi(stack0)
    cincoffset ca0, ca0, %pcrel_lo(next)

    lui a6, 1000
    addi a6, a6, 1000


  cfromptr c11, cgp, t0
 csetbounds c11, c11, 8
 clbu a0,7(c11)
 clbu a1,8(c11)

    li        t2, 4096
    csrr      t3, mhartid
    addi      t3, t3, 1
    mul       t4, t2, t3


    csetaddr  csp, ct1, a0
    csetbounds csp, csp, t4
    cincoffset csp, csp, t4

3:
    auipcc    ca0, %pcrel_hi(start)
    cincoffset ca0, ca0, %pcrel_lo(3b)
    cjalr     cra, ca0              # call start()

spin:
    j spin
