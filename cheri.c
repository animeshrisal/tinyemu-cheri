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

// BOOL set_cap_bounds (capability_t cap, cap_address_bits_t a, cap_len_bits_t l,
// capability_t *cap) {

// }

// BOOL set_cap_addr (capability_t cap, cap_address_bits_t a, capability_t
// *capability) {

// }

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

uint64_t inline bool_to_bits(BOOL sealed) { return 1; }

uint64_t inline get_cap_high(capability_t cap) { return 1; }

uint64_t inline get_cap_top(capability_t cap) { return 1; }

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
  SetCapOffsetResult result;
  return result;
};


SetCapBoundsResult set_cap_bounds(capability_t cap) {
  SetCapBoundsResult result;
  return result;
};

capability_t set_cap_flags(capability_t cap, uint64_t rv) {
  return cap;
}

uint64_t set_cap_offsetBits(capability_t cap, uint64_t reg) { 
  return 1;
};

SetCapAddrResult set_cap_addr(capability_t cap, uint64_t vl) {
  SetCapAddrResult cap2;
  return cap2;
}

CapAddrResult inc_cap_offset(capability_t cap, uint64_t reg) {
  CapAddrResult addr;
  return addr;
}

BOOL in_cap_bounds(capability_t cap, uint64_t vl, uint64_t al) {

}

uint64_t get_cap_base_bits(capability_t cap) {
  return 1;
}

capability_t set_cap_perms(capability_t cap, uint64_t cap_perm_bits) {
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


// inline BOOL CSpecialRW(int cd, int scr, int cs1, RISCVCapabilityState cs, RISCVCPUState s) {
//     SpecialCapabilityRegister info = get_special_reg_info(scr, haveNExt(), haveSupMode());

//     // if (!info.exists || 
//     //     (info.readOnly && cs1 != 0) || 
//     //     (privLevel_to_bits(cur_privilege()) < privLevel_to_bits(info.requiredPrivilege))) {
//     //     handle_illegal();
//     //     return FALSE;
//     // }
//     // if (info.needsASRPerm && !pcc_access_system_regs()) {
//     //     handle_cheri_cap_exception(CapEx_AccessSystemRegsViolation, (0b1 << 5) | scr);
//     //     return FALSE;
//     // }

//     capability_t cs1 = s->cd[cs1];

//     switch (scr) {
//         case 0: s->cap(cd) = set_cap_addr(state.pcc, state.pcc).second; break;
//         case 1: s->cap(cd) = state.ddc; break;
//         case 4: s->cap(cd) = state.utcc; break;
//         case 5: s->cap(cd) = state.utdc; break;
//         case 6: s->cap(cd) = state.uscratchc; break;
//         case 7: s->cap(cd) = legalize_epcc(state.uepcc); break;
//         case 12: s->cap(cd) = state.stcc; break;
//         case 13: s->cap(cd) = state.stdc; break;
//         case 14: s->cap(cd) = state.sscratchc; break;
//         case 15: s->cap(cd) = legalize_epcc(state.sepcc); break;
//         case 28: s->cap(cd) = state.mtcc; break;
//         case 29: s->cap(cd) = state.mtdc; break;
//         case 30: s->cap(cd) = state.mscratchc; break;
//         case 31: s->cap(cd) = legalize_epcc(state.mepcc); break;
//         default: assert(FALSE && "unreachable"); return FALSE;
//     }

//         // Write to special register if cs1 is not C0
//     if (cs1 != 0) {
//         switch (scr) {
//             case 1: state.ddc; = cs1; break;
//             case 4: state.utcc = legalize_tcc(state.utcc, cs1); break;
//             case 5: state.utdc = cs1; break;
//             case 6: state.uscratchc = cs1; break;
//             case 7: state.uepcc = cs1; break;
//             case 12: state.stcc = legalize_tcc(statie.stcc, cs1); break;
//             case 13: state.stdc = cs1; break;
//             case 14: state.sscratchc = cs1; break;
//             case 15: state.sepcc = cs1; break;
//             case 28: state.mtcc = legalize_tcc(state.mtcc, cs1); break;
//             case 29: state.mtdc = cs1; break;
//             case 30: state.mscratchc = cs1; break;
//             case 31: state.mepcc = cs1; break;
//             default: assert(FALSE && "unreachable"); return FALSE;
//         }
//         if (get_config_print_reg()) {
//             printf("%s <- %s\n", scr_name_map(scr), RegStr(cs1));
//         }
//     }

//     return TRUE;
// }