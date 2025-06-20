#ifndef CHERI_H
#define CHERI_H

#include <stdlib.h>
#include "cutils.h"

#define CAP_ADDR_WIDTH XLEN
#define CAP_LEN_WIDTH (CAP_ADDR_WIDTH + 1)
#define CAP_SIZE 16
#define CAP_MANTISSA_WIDTH 14
#define CAP_HPERMS_WIDTH 14
#define CAP_UPERMS_WIDTH 4
#define CAP_UPERMS_SHIFT 15
#define CAP_FLAGS_WIDTH 1
#define CAP_OTYPE_WIDTH 18
#define RESERVED_OTYPES 4
#define CAP_MAX_OTYPE ((1 << CAP_OTYPE_WIDTH) - RESERVED_OTYPES)
#define CAPS_PER_CACHE_LINE 4


typedef enum ExceptionType {
    None                          = 0x0,
    LengthViolation               = 0x1,
    TagViolation                  = 0x2,
    SealViolation                 = 0x3,
    TypeViolation                 = 0x4,
    CallTrap                      = 0x5,
    ReturnTrap                    = 0x6,
    TSSUnderFlow                  = 0x7,
    UserDefViolation              = 0x8,
    TLBNoStoreCap                 = 0x9,
    InexactBounds                 = 0xA,
    UnalignedBase                 = 0xB,
    CapLoadGen                    = 0xC,

    GlobalViolation               = 0x10,
    PermitExecuteViolation        = 0x11,
    PermitLoadViolation           = 0x12,
    PermitStoreViolation          = 0x13,
    PermitLoadCapViolation        = 0x14,
    PermitStoreCapViolation       = 0x15,
    PermitStoreLocalCapViolation  = 0x16,
    PermitSealViolation           = 0x17,
    AccessSystemRegsViolation     = 0x18,
    PermitCCallViolation          = 0x19,
    AccessCCallIDCViolation       = 0x1A,
    PermitUnsealViolation         = 0x1B,
    PermitSetCIDViolation         = 0x1C,
} ExceptionType;



typedef struct {
  uint64_t base;
  uint64_t length;
  uint64_t offset;
  uint64_t permissions;
  uint64_t uperissions;
  uint64_t flags;
  uint64_t otype;
  uint8_t tag;
} cap_register_t;



typedef cap_register_t capability_t;

typedef struct {
  cap_register_t pcc;
  cap_register_t ddc;

  cap_register_t mtcc;
  cap_register_t mtdc;
  cap_register_t mscratchc;
  cap_register_t mepcc;

  cap_register_t stcc;      // SCR 12 Supervisor trap code cap. (STCC)
  cap_register_t stdc;      // SCR 13 Supervisor trap data cap. (STDC)
  cap_register_t sscratchc; // SCR 14 Supervisor scratch cap. (SScratchC)
  cap_register_t sepcc;     // SCR 15 Supervisor exception PC cap. (SEPCC)

  cap_register_t utcc;
  cap_register_t utdc;      // SCR 5 User trap data cap. (UTDC)
  cap_register_t uscratchc; // SCR 6 User scratch cap. (UScratchC)
  cap_register_t uepcc;     // SCR 7 User exception PC cap. (UEPCC)

  cap_register_t vstcc;
  cap_register_t vstdc;
  cap_register_t vsscratchc;
  cap_register_t vsepcc;

  cap_register_t stcc_hs;
  cap_register_t sepcc_hs;

} RISCVCapabilityState;

typedef enum {
  USER,
  SUPERVISOR,
  MACHINE
} Privilege;

typedef struct {
  uint64_t base;
  uint64_t top;
} CapBounds;

typedef struct {
    BOOL success;
    capability_t cap;
} CapAddrResult;

typedef struct {
    BOOL exact;
    capability_t cap;
} SetCapBoundsResult;

typedef struct {
    BOOL exact;
    capability_t cap;
} SetCapAddrResult;

typedef struct {
    BOOL success;
    capability_t cap;
} SetCapOffsetResult;

typedef struct {
  BOOL specialExists;
  BOOL ro;
  uint8_t privilege;
  BOOL needASR;
} SpecialCapabilityRegister;


void insert_entry(capability_t cap);
capability_t *get_entry(uint64_t base_addr);
capability_t get_register(int n);
capability_t clearTag(capability_t cap);
capability_t clearTagIf(capability_t cap, BOOL condition);
capability_t clearTagIfSealed(capability_t cap);
capability_t unSealCap(capability_t cap);
BOOL isCapSealed(capability_t cap);
uint64_t getCapPerms(capability_t cap);
capability_t setCapPerms(capability_t cap, uint64_t cap_perm_bits);
BOOL hasReservedOType(capability_t cap);
uint64_t getCapabilityBaseBits(capability_t cap);
uint64_t getCapLength(capability_t cap);
uint64_t getCapOffsetBits(capability_t cap);
uint64_t setCapOffsetBits(capability_t cap, uint64_t reg);
uint64_t EXTZ(uint64_t flags);
uint64_t getCapFlags(capability_t cap);
uint64_t bool_to_bits(BOOL sealed);
uint64_t getCapHigh(capability_t cap);
uint64_t getCapTop(capability_t cap);
uint64_t getBasePermBits(capability_t cap);
uint64_t EXTZ(uint64_t flags);
uint64_t EXTS(uint64_t flags);
CapBounds getCapBounds(capability_t cap);
SetCapBoundsResult setCapBounds(capability_t cap);
SetCapAddrResult setCapAddr(capability_t cap, uint64_t vl);
SetCapOffsetResult setCapOffset(capability_t cap, uint64_t vl);

uint64_t getCapabilityBaseBits(capability_t cap);
uint64_t getCapCursor(capability_t cap);
capability_t sealCap(capability_t cap);
uint64_t getRepresentableAlighmentMask(uint64_t xlenbits);

uint8_t handleIllegal();
uint8_t handleMemException(uint64_t xlenbits, ExceptionType type);
uint8_t handleCheriCapException(uint64_t cap_ex, uint64_t capreg_idx);
uint8_t handleCheriRegException(uint64_t cap_ex, uint64_t capreg_idx);
uint8_t handleCheriPCCException(uint64_t cap_ex);

uint64_t toBits(int value, int width);

capability_t setCapFlags(capability_t cap, uint64_t rv);
CapAddrResult incCapOffset(capability_t cap, uint64_t reg);
BOOL inCapBounds(capability_t cap, uint64_t vl, uint64_t al);
uint64_t getCapBaseBits(capability_t cap);
SetCapBoundsResult setCapBounds(capability_t cap);

void capSpecialRW();
SpecialCapabilityRegister getSpecialRegInfo(uint64_t csr, BOOL val, Privilege priv);
BOOL haveNExt();
BOOL haveSupMode();
capability_t legalize_epcc(capability_t cap);
capability_t legalize_tcc(capability_t cap1, capability_t cap2);

#endif

