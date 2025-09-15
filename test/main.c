#include <stdint.h>
#include <stddef.h>
#include <cheriintrin.h>
#include <cheri/cheri.h>
#include <cheri_init_globals.h>


int main(void); 

__attribute__((aligned(16))) char stack0[4096];

struct uart {
   union {
     volatile uint8_t THR;
     volatile uint8_t RBR;
     volatile uint8_t DLL;
   };
   union {
     volatile uint8_t IER;
     volatile uint8_t DLH;
   };
   union {
     volatile uint8_t IIR;
     volatile uint8_t FCR;
   };
   volatile uint8_t LCR;
   volatile uint8_t MCR;
   volatile uint8_t LSR;
};

// Global capability variable for UART0 
// Linker emits a capreloc entry to initialize it automatically
volatile struct uart* __capability uart0;

static volatile struct uart* __capability get_uart0(void) {
    void *__capability base = cheri_ddc_get();
    base = __builtin_cheri_cap_from_pointer(base,0x10000000);
    base = cheri_bounds_set(base, sizeof(struct uart));
    return (volatile struct uart* __capability)base;
}

void putachar(volatile struct uart* __capability uart0, char c) {
    while ((uart0->LSR & (1 << 5)) == 0);
    uart0->THR = c;
}

void printstring(const char *s) {
    for (size_t i = 0; s[i] != '\0'; i++) {
        putachar(uart0, s[i]);
    }
}


void start(void) {
    // Initialize the global data capability
    // This is required to use the CHERI global data feature
    // and to ensure that the global data capability is set up correctly
    // This function is typically provided by the CHERI runtime

    cheri_init_globals();
    main();
    while (1);
}

int main(void) {
    uart0 = get_uart0();
    printstring("Hallo RISC-V!\n");
    uart0[45];
    return 0;
}
