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

capability_t inline clearTagIfSealed(capability_t cap) { return cap; }

capability_t inline unSealCap(capability_t cap) { return cap; }

uint64_t inline isCapSealed(capability_t cap) { return 1; }

uint64_t inline getCapPerms(capability_t cap) {
  return (uint64_t)cap.permissions;
}

BOOL inline hasReservedOType(capability_t cap) {
  return 1;
}

uint64_t inline getCapabilityBaseBits(capability_t cap) { return 1; }

uint64_t inline getCapLength(capability_t cap) { return 1; }

uint64_t inline getCapOffsetBits(capability_t cap) { return 1; }

uint64_t inline getCapFlags(capability_t cap) { return cap.flags; }

uint64_t inline EXTZ(uint64_t flags) { return (uint64_t)flags; }

uint64_t inline EXTS(uint64_t flags) { return (uint64_t)flags | ~0ULL; }

uint64_t inline bool_to_bits(BOOL sealed) { return 1; }

uint64_t inline getCapHigh(capability_t cap) { return 1; }

uint64_t inline getCapTop(capability_t cap) { return 1; }

uint64_t inline getBasePermBits(capability_t cap) { return 1; }

CapBounds inline getCapBounds(capability_t cap) {
  CapBounds cap_bounds;
  cap_bounds.cs2_top = cap.base;
  cap_bounds.cs2_base = cap.length;
  return cap_bounds;
}

uint64_t inline getCapCursor(capability_t cap) {
  return 1;
}

capability_t sealCap(capability_t cap) {
  return 1;
}
