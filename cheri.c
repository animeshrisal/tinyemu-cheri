#include "cheri.h"
#include <stdint.h>
#include <string.h>
#include "cutils.h"

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

// BOOL setCapBounds (capability_t cap, cap_address_bits_t a, cap_len_bits_t l, capability_t *cap) {

// }

// BOOL setCapAddr (capability_t cap, cap_address_bits_t a, capability_t *capability) {

// }

capability_t clearTag(capability_t cap) {
    cap.tag = 0;
    return cap;
}

capability_t clearTagIf(capability_t cap, BOOL bool) {
    if(bool == 1) {
        cap.tag = 1;
    }
    return cap;
}

capability_t clearTagIfSealed(capability_t cap) {
    return cap;
}

capability_t unSealCap(capability_t cap) {
   return cap;
}

uint64_t isCapSealed(capability_t cap) {
    return 1;
}

uint64_t inline getCapPerms(capability_t cap) {
    return (uint64_t)cap.permissions;
}

BOOL hasReservedOType(capability_t cap) {

}

uint64_t getCapabilityBaseBits(capability_t cap) {
    return 1;
}

uint64_t getCapLength(capability_t cap) {
    return 1;
}

uint64_t getCapOffsetBits(capability_t cap) {
    return 1;
}

uint64_t getCapFlags(capability_t cap) {
    return 1;
}

uint64_t EXTZ(uint64_t flags) {
    return (uint64_t)flags;
}

uint64_t EXTS(u_int64_t flags) {
return (uint64_t)flags | ~0ULL;
}

uint64_t bool_to_bits(BOOL sealed) {
    return 1;
}
