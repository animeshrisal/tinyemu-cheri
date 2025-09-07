#include "cheri.h"
#include "cutils.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Set a max counter capabilities of 1000
  Since we are not directly saving the capabilities in the memory. 
  We are using a workaround where we store the capabilities in a table.
  When we perform memory operations, we are reading from the table instead of the RAM>
  This is not the best method but it works for now
*/
#define MAX_COUNTER 1000
int counter = 0;


/*
 We store the two values. The address of the memory location is the key. 
 The value is the pointer to the where the capability is actually stored.
 */
typedef struct {
  uint64_t key;
  capability_t *value;
} cap_table_entry_t;


/* 
  The table
*/
typedef struct {
  cap_table_entry_t entry[MAX_COUNTER];
} cap_table_t;

cap_table_t table;


static inline uint64_t cap_top(const capability_t *cap) {
  return cap->base + cap->length;
}

void insert_entry(uint64_t addr, capability_t cap) {
  if (counter < MAX_COUNTER) {
    table.entry[counter].key = addr;
    table.entry[counter].value = &cap;
    counter = (counter + 1) % MAX_COUNTER ;
  }
}

capability_t *get_entry(uint64_t base_addr) {
  for (int i = 0; i < counter; i++) {
    if (table.entry[counter].key == base_addr) {

      return &table.entry[counter].value;
    }
  }

  capability_t new_cap;
  return &new_cap;
}

capability_t get_register(int n) {

}

capability_t inline clear_tag(capability_t cap) {
  cap.tag = 0;
  return cap;
}

capability_t inline clear_tag_if(capability_t cap, BOOL bool) {
  if (bool == 1) {
    cap.tag = 1;
  }
  return cap;
}

capability_t inline clear_tag_if_sealed(capability_t cap) {
  if(is_cap_sealed(cap)) {
    cap.tag = 0;
  }
  return cap; 
}

capability_t inline seal_cap(capability_t cap) { 
  return cap;
}

capability_t inline unseal_cap(capability_t cap) { return cap; }

BOOL inline is_cap_sealed(capability_t cap) { 
  return cap.otype == 1 ? 1 : 0;
}

uint64_t inline get_cap_perms(capability_t cap) {
  return (uint64_t)cap.permissions;
}

BOOL inline has_reserved_otype(capability_t cap) {
  return (uint64_t)cap.otype;
}

uint64_t inline get_capability_base_bits(capability_t cap) { return 1; }

uint64_t inline get_cap_length(capability_t cap) { return (uint64_t)cap.length; }

uint64_t inline get_cap_offset_bits(capability_t cap) { return (uint64_t)cap.offset; }

uint64_t inline get_cap_flags(capability_t cap) { return cap.flags; }

uint64_t inline EXTZ(uint64_t flags) { return (uint64_t)flags; }

uint64_t inline EXTS(uint64_t flags) { return (uint64_t)flags | ~0ULL; }

uint64_t inline get_cap_high(capability_t cap) { return 1; }

uint64_t inline get_cap_top(capability_t cap) { return cap_top(&cap); }

uint64_t inline get_base_perm_bits(capability_t cap) { return (uint64_t)cap.base; }

CapBounds inline get_cap_bounds(capability_t cap) {
  CapBounds cap_bounds;
  cap_bounds.top = cap.base;
  cap_bounds.base = cap.length;
  return cap_bounds;
}

uint64_t inline get_cap_cursor(capability_t cap) {
  return 1;
}

uint64_t inline to_bits(int value, int width) {
  return (uint64_t)(value & ((1ULL << width) - 1 ));
}

SetCapOffsetResult set_cap_offset(capability_t cap, uint64_t val) {
  cap.offset = val;
  SetCapOffsetResult result = { 1, cap };
  return result;
};

SetCapBoundsResult set_cap_bounds(capability_t cap, uint64_t newBase, uint64_t newTop) {
  cap.base = newBase;
  cap.length = newTop - newBase;
  SetCapBoundsResult result = { 1, cap};

  return result;
};

capability_t set_cap_flags(capability_t cap, uint64_t rv) {
  cap.flags = rv;
  return cap;
}

uint64_t set_cap_offsetBits(capability_t cap, uint64_t reg) { 
  return 1;
};

SetCapAddrResult set_cap_addr(capability_t cap, uint64_t vl) {
  capability_t new_cap = cap;
  new_cap.offset = (uint64_t)(vl);
  BOOL within_bounds = (vl >= cap.base) && (vl < cap.base + cap.length);
  // BOOL representable = within_bounds && capBoundsEqual(cap, new_cap);

  SetCapAddrResult result = { 1, new_cap };
  return result;
}

CapAddrResult inc_cap_offset(capability_t cap, uint64_t reg) {
  cap.offset += reg;
  CapAddrResult addr = { 1, cap };
  return addr;
}

BOOL in_cap_bounds(capability_t cap, uint64_t vl, uint64_t al) {

}

uint64_t get_cap_base_bits(capability_t cap) {
  return 1;
}

capability_t set_cap_perms(capability_t cap, uint64_t cap_perm_bits) {
  cap.permissions = cap_perm_bits;
  return cap;
}

capability_t set_cap_uperms(capability_t cap, uint64_t cap_perm_bits) {
  cap.upermissions = cap_perm_bits;
  return cap;
}

SpecialCapabilityRegister get_special_reg_info(uint64_t csr, BOOL val, Privilege priv) {
  int haveNExt = 1;
  int haveSupMode = 1;

  switch(csr) {
      case 0: return (SpecialCapabilityRegister){TRUE, TRUE, USER, FALSE};
      case 1: return (SpecialCapabilityRegister){TRUE, FALSE, USER, FALSE};
      case 4: case 5: case 6: case 7:
        if (haveNExt) return (SpecialCapabilityRegister){TRUE, FALSE, USER, TRUE}; break;
      case 12: case 13: case 14: case 15:
        if (haveSupMode) return (SpecialCapabilityRegister){TRUE, FALSE, SUPERVISOR, TRUE}; break;
      case 28: case 29: case 30: case 31:
        return (SpecialCapabilityRegister){TRUE, FALSE, MACHINE, TRUE};
      default: return (SpecialCapabilityRegister){FALSE, TRUE, MACHINE, TRUE};
    }
    return (SpecialCapabilityRegister){FALSE, TRUE, MACHINE, TRUE};
  }

BOOL inline haveNExt() {
  return TRUE;
}

BOOL inline haveSupMode() {
  return MACHINE;
}

capability_t legalize_epcc(capability_t cap) {
  return cap;
}

capability_t legalize_tcc(capability_t cap1, capability_t cap2) {
  return cap1;
}

uint8_t handle_cheri_reg_exception(uint64_t cap_ex, uint64_t capreg_idx) {

}

uint8_t handle_mem_exception(uint64_t xlenbits, ExceptionType type) {
  
}

BOOL capability_equals(capability_t c1, capability_t c2) {
    return (c1.base        == c2.base)        &&
           (c1.length      == c2.length)      &&
           (c1.offset      == c2.offset)      &&
           (c1.permissions == c2.permissions) &&
           (c1.upermissions== c2.upermissions)&&
           (c1.flags       == c2.flags)       &&
           (c1.otype       == c2.otype)       &&
           (c1.tag         == c2.tag)         &&
           (c1._cap_cursor == c2._cap_cursor);
}

const char* cheri_reg_name(int index) {
    switch (index) {
        case 0:  return "cnull";   // zero register
        case 1:  return "cra";     // stack pointer
        case 2:  return "csp";     // return address
        case 3:  return "cgp";     // global pointer
        case 4:  return "ctp";     // thread pointer
        case 5:  return "ct0";      // reserved or ABI-defined
        case 6:  return "ct1";      // reserved or ABI-defined
        case 7:  return "ct2";     // frame pointer

        case 8:  return "cs0";
        case 9:  return "cs1";
        case 10: return "ca0";
        case 11: return "ca1";
        case 12: return "ca2";
        case 13: return "ca3";
        case 14: return "ca4";
        case 15: return "ca5";

        case 16: return "ca6";
        case 17: return "ca7";
        case 18: return "cs2";
        case 19: return "cs3";
        case 20: return "cs5";
        case 21: return "cs6";
        case 22: return "cs6";
        case 23: return "cs7";
        case 24: return "cs8";
        case 25: return "cs9";
        case 26: return "cs10";

        case 27: return "cs11";
        case 28: return "ct3";
        case 29: return "ct4";
        case 30: return "ct5";
        case 31: return "ct6";
        case 32: return "pcc";
        case 33: return "ddc";

        default: return "invalid";
    }
}

void capability_print(cap_register_t cap, int index) {
    const char* reg_name = cheri_reg_name(index);
    printf("--------- Capability Register %s ---------\n", reg_name);
    printf("Base       : 0x%llx\n", cap.base);
    printf("Length     : 0x%llx\n", cap.length);
    printf("Offset     : 0x%llx\n", cap.offset);
    printf("Permissions: 0x%llx\n", cap.permissions);
    printf("upermissions: 0x%llx\n", cap.upermissions); 
    printf("Flags      : 0x%llx\n", cap.flags);
    printf("Otype      : 0x%llx\n", cap.otype);
    printf("Tag        : 0x%x\n", cap.tag);
    printf("Cursor     : 0x%llx\n", cap._cap_cursor);
    printf("--------------------------------\n");
}

