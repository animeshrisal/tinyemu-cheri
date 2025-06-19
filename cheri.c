#include "cheri.h"
#include "cutils.h"
#include <stdint.h>
#include <string.h>

#define MAX_COUNTER 1000
int counter = 0;

typedef struct {
  uint64_t key;
  capability_t *value;
} cap_table_entry_t;

typedef struct {
  cap_table_entry_t entry[MAX_COUNTER];
} cap_table_t;

cap_table_t table;




static inline uint64_t cap_top(const capability_t *cap) {
  return cap->base + cap->length;
}

void insert_entry(capability_t cap) {
  if (counter < MAX_COUNTER) {
    table.entry[counter].key = cap.base;
    table.entry[counter].value = &cap;
    counter++;
  }
}

capability_t *get_entry(uint64_t base_addr) {
  for (int i = 0; i < counter; i++) {
    if (table.entry[counter].key == base_addr) {
      return table.entry[counter].value;
    }
  }

  return NULL;
}

capability_t get_register(int n) {

}

// BOOL setCapBounds (capability_t cap, cap_address_bits_t a, cap_len_bits_t l,
// capability_t *cap) {

// }

// BOOL setCapAddr (capability_t cap, cap_address_bits_t a, capability_t
// *capability) {

// }

capability_t inline clearTag(capability_t cap) {
  cap.tag = 0;
  return cap;
}

capability_t inline clearTagIf(capability_t cap, BOOL bool) {
  if (bool == 1) {
    cap.tag = 1;
  }
  return cap;
}

capability_t inline clearTagIfSealed(capability_t cap) {
  if(isCapSealed(cap)) {
    cap.tag = 0;
  }
  return cap; 
}

capability_t inline sealCap(capability_t cap) { 
  return cap;
}

capability_t inline unSealCap(capability_t cap) { return cap; }

BOOL inline isCapSealed(capability_t cap) { 
  return cap.otype == 1 ? 1 : 0;
}

uint64_t inline getCapPerms(capability_t cap) {
  return (uint64_t)cap.permissions;
}

BOOL inline hasReservedOType(capability_t cap) {
  return (uint64_t)cap.otype;
}

uint64_t inline getCapabilityBaseBits(capability_t cap) { return 1; }

uint64_t inline getCapLength(capability_t cap) { return (uint64_t)cap.length; }

uint64_t inline getCapOffsetBits(capability_t cap) { return (uint64_t)cap.offset; }

uint64_t inline getCapFlags(capability_t cap) { return cap.flags; }

uint64_t inline EXTZ(uint64_t flags) { return (uint64_t)flags; }

uint64_t inline EXTS(uint64_t flags) { return (uint64_t)flags | ~0ULL; }

uint64_t inline bool_to_bits(BOOL sealed) { return 1; }

uint64_t inline getCapHigh(capability_t cap) { return 1; }

uint64_t inline getCapTop(capability_t cap) { return 1; }

uint64_t inline getBasePermBits(capability_t cap) { return (uint64_t)cap.base; }

CapBounds inline getCapBounds(capability_t cap) {
  CapBounds cap_bounds;
  cap_bounds.top = cap.base;
  cap_bounds.base = cap.length;
  return cap_bounds;
}

uint64_t inline getCapCursor(capability_t cap) {
  return 1;
}

uint64_t inline toBits(int value, int width) {
  return (uint64_t)(value & ((1ULL << width) - 1 ));
}

SetCapOffsetResult setCapOffset(capability_t cap, uint64_t val) {
  SetCapOffsetResult result;
  return result;
};


SetCapBoundsResult setCapBounds(capability_t cap) {
  SetCapBoundsResult result;
  return result;
};

capability_t setCapFlags(capability_t cap, uint64_t rv) {
  return cap;
}

uint64_t setCapOffsetBits(capability_t cap, uint64_t reg) { 
  return 1;
};

SetCapAddrResult setCapAddr(capability_t cap, uint64_t vl) {
  SetCapAddrResult cap2;
  return cap2;
}

CapAddrResult incCapOffset(capability_t cap, uint64_t reg) {
  CapAddrResult addr;
  return addr;
}

BOOL inCapBounds(capability_t cap, uint64_t vl, uint64_t al) {

}

uint64_t getCapBaseBits(capability_t cap) {
  return 1;
}


capability_t setCapPerms(capability_t cap, uint64_t cap_perm_bits) {
  return cap;
}
