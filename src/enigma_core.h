#ifndef ENIGMA_CORE_H
#define ENIGMA_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MODE_M3 = 0, // mu = 0: 3-rotor M3 (Beta fixed at A/A + UKW-B thin == UKW-B)
    MODE_M4 = 1  // mu = 1: 4-rotor Naval M4 (Beta/Gamma unlocked + thin reflectors)
} EnigmaMode;

typedef enum {
    ROTOR_I = 0,
    ROTOR_II,
    ROTOR_III,
    ROTOR_IV,
    ROTOR_V,
    ROTOR_VI,
    ROTOR_VII,
    ROTOR_VIII,
    ROTOR_BETA,
    ROTOR_GAMMA,
    ROTOR_COUNT
} RotorID;

typedef enum {
    UKW_B = 0,
    UKW_C,
    UKW_B_THIN,
    UKW_C_THIN,
    UKW_COUNT
} ReflectorID;

typedef struct {
    EnigmaMode mode;
    uint8_t rotor_id[4];   // Signal path order: [0]=Right, [1]=Middle, [2]=Left, [3]=Greek
    uint8_t ukw_id;        // ReflectorID
    uint8_t pos[4];        // Current window state x[t] in 0..25
    uint8_t ring[4];       // Ringstellung r in 0..25
    uint8_t delta[4];      // Net phase: (pos[i] - ring[i] + 26) % 26
    uint8_t fwd[4][26];    // Forward wheel LUTs
    uint8_t inv[4][26];    // Inverse wheel LUTs
    uint8_t ukw[26];       // Reflector involution LUT
    uint8_t plugboard[26]; // Reciprocal Steckerbrett LUT
} EnigmaMachine;

bool enigma_init(
    EnigmaMachine *m,
    EnigmaMode mode,
    const uint8_t rotors_lr[],
    uint8_t ukw_id,
    const uint8_t start_lr[],
    const uint8_t rings_lr[],
    const char *plug_pairs
);

void enigma_step(EnigmaMachine *m);
uint8_t enigma_crypt_char(EnigmaMachine *m, uint8_t c);
size_t enigma_crypt_buffer(EnigmaMachine *m, const char *in, char *out, bool strip_non_alpha);
int enigma_run_self_tests(bool verbose);

int enigma_cli_crypt(
    int mode, int r0, int r1, int r2, int r3, int ukw,
    const char *start_str, const char *rings_str, const char *plugs_str,
    const char *in_text, char *out_text
);

#ifdef __cplusplus
}
#endif

#endif // ENIGMA_CORE_H
