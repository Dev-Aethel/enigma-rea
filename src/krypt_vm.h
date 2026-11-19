#ifndef KRYPT_VM_H
#define KRYPT_VM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OP_HALT             = 0x00,
    OP_SET_MODE         = 0x01, // [mode: 0=M3, 1=M4]
    OP_SET_CRIB         = 0x02, // [pos_min, pos_max, weight_x10, len, c0..cN-1]
    OP_SET_EDIT_DROP    = 0x03, // [drop_index, penalty_x10] (tests deleting 1 garbled char)
    OP_SWEEP_IC         = 0x04, // [greek_mask, rotor_mask, ukw_mask, keep_top]
    OP_TUNE_RINGS       = 0x05, // [keep_top]
    OP_CLIMB_PLUGS      = 0x06  // [max_iters_hi, max_iters_lo]
} KryptOpcode;

// Execute a compiled KryptScript bytecode program against ciphertext and write JSON report
int krypt_vm_execute(
    const uint8_t *bytecode,
    size_t bc_len,
    const char *ciphertext,
    char *json_report_out,
    size_t max_out_len
);

#ifdef __cplusplus
}
#endif

#endif // KRYPT_VM_H
