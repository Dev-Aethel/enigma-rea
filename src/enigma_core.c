#include "enigma_core.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const char *ROTOR_WIRING[ROTOR_COUNT] = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ", // I
    "AJDKSIRUXBLHWTMCQGZNPYFVOE", // II
    "BDFHJLCPRTXVZNYEIWGAKMUSQO", // III
    "ESOVPZJAYQUIRHXLNFTGKDCMWB", // IV
    "VZBRGITYUPSDNHLXAWMJQOFECK", // V
    "JPGVOUMFYQBENHZRDKASXLICTW", // VI
    "NZJHGRCXMYSWBOUFAIVLPEKQDT", // VII
    "FKQHTLXOCBJSPDZRAMEWNIUYGV", // VIII
    "LEYJVCNIXWPBQMDRTAKZGFUHOS", // Beta
    "FSOKANUERHMBTIYCWLQPZXVGJD"  // Gamma
};

static const uint32_t ROTOR_NOTCH_MASK[ROTOR_COUNT] = {
    (1u << ('Q' - 'A')),                        // I: Q
    (1u << ('E' - 'A')),                        // II: E
    (1u << ('V' - 'A')),                        // III: V
    (1u << ('J' - 'A')),                        // IV: J
    (1u << ('Z' - 'A')),                        // V: Z
    (1u << ('Z' - 'A')) | (1u << ('M' - 'A')),  // VI: Z, M
    (1u << ('Z' - 'A')) | (1u << ('M' - 'A')),  // VII: Z, M
    (1u << ('Z' - 'A')) | (1u << ('M' - 'A')),  // VIII: Z, M
    0u,                                         // Beta
    0u                                          // Gamma
};

static const char *UKW_WIRING[UKW_COUNT] = {
    "YRUHQSLDPXNGOKMIEBFZCWVJAT", // UKW-B
    "FVPJIAOYEDRZXWGCTKUQSBNMHL", // UKW-C
    "ENKQAUYWJICOPBLMDXZVFTHRGS", // UKW-B thin
    "RDOBJNTKVEHMLFCWZAXGYIPSUQ"  // UKW-C thin
};

static inline uint8_t wrap26_add(uint8_t a, uint8_t b) {
    uint8_t s = a + b;
    return (s >= 26) ? (s - 26) : s;
}

static inline uint8_t wrap26_sub(uint8_t a, uint8_t b) {
    return (a >= b) ? (a - b) : (a + 26 - b);
}

static inline bool is_at_notch(uint8_t rotor_id, uint8_t pos) {
    return (ROTOR_NOTCH_MASK[rotor_id] & (1u << pos)) != 0;
}

static void load_rotor_slot(EnigmaMachine *m, int slot, uint8_t rotor_id, uint8_t pos, uint8_t ring) {
    m->rotor_id[slot] = rotor_id;
    m->pos[slot]      = pos % 26;
    m->ring[slot]     = ring % 26;
    m->delta[slot]    = wrap26_sub(m->pos[slot], m->ring[slot]);

    const char *w = ROTOR_WIRING[rotor_id];
    for (uint8_t i = 0; i < 26; i++) {
        uint8_t out = (uint8_t)(w[i] - 'A');
        m->fwd[slot][i]   = out;
        m->inv[slot][out] = i;
    }
}

bool enigma_init(
    EnigmaMachine *m,
    EnigmaMode mode,
    const uint8_t rotors_lr[],
    uint8_t ukw_id,
    const uint8_t start_lr[],
    const uint8_t rings_lr[],
    const char *plug_pairs
) {
    if (!m || !rotors_lr || !start_lr || !rings_lr || ukw_id >= UKW_COUNT) {
        return false;
    }

    memset(m, 0, sizeof(*m));
    m->mode   = mode;
    m->ukw_id = ukw_id;

    for (uint8_t i = 0; i < 26; i++) {
        m->ukw[i] = (uint8_t)(UKW_WIRING[ukw_id][i] - 'A');
        m->plugboard[i] = i;
    }

    if (mode == MODE_M3) {
        load_rotor_slot(m, 0, rotors_lr[2], start_lr[2], rings_lr[2]);
        load_rotor_slot(m, 1, rotors_lr[1], start_lr[1], rings_lr[1]);
        load_rotor_slot(m, 2, rotors_lr[0], start_lr[0], rings_lr[0]);
        load_rotor_slot(m, 3, ROTOR_BETA, 0, 0);
    } else {
        load_rotor_slot(m, 0, rotors_lr[3], start_lr[3], rings_lr[3]);
        load_rotor_slot(m, 1, rotors_lr[2], start_lr[2], rings_lr[2]);
        load_rotor_slot(m, 2, rotors_lr[1], start_lr[1], rings_lr[1]);
        load_rotor_slot(m, 3, rotors_lr[0], start_lr[0], rings_lr[0]);
    }

    if (plug_pairs) {
        bool used[26] = {false};
        const char *p = plug_pairs;
        while (*p) {
            while (*p && !isalpha((unsigned char)*p)) p++;
            if (!*p) break;
            char c1 = (char)toupper((unsigned char)*p++);
            while (*p && !isalpha((unsigned char)*p)) p++;
            if (!*p) return false;
            char c2 = (char)toupper((unsigned char)*p++);

            uint8_t a = (uint8_t)(c1 - 'A');
            uint8_t b = (uint8_t)(c2 - 'A');
            if (a == b || used[a] || used[b]) return false;
            used[a] = used[b] = true;
            m->plugboard[a] = b;
            m->plugboard[b] = a;
        }
    }

    return true;
}

void enigma_step(EnigmaMachine *m) {
    bool mid_notch   = is_at_notch(m->rotor_id[1], m->pos[1]);
    bool right_notch = is_at_notch(m->rotor_id[0], m->pos[0]);

    if (mid_notch) {
        m->pos[2]   = wrap26_add(m->pos[2], 1);
        m->delta[2] = wrap26_sub(m->pos[2], m->ring[2]);
        m->pos[1]   = wrap26_add(m->pos[1], 1);
        m->delta[1] = wrap26_sub(m->pos[1], m->ring[1]);
    } else if (right_notch) {
        m->pos[1]   = wrap26_add(m->pos[1], 1);
        m->delta[1] = wrap26_sub(m->pos[1], m->ring[1]);
    }

    m->pos[0]   = wrap26_add(m->pos[0], 1);
    m->delta[0] = wrap26_sub(m->pos[0], m->ring[0]);
}

uint8_t enigma_crypt_char(EnigmaMachine *m, uint8_t c) {
    enigma_step(m);
    c = m->plugboard[c];

    for (int i = 0; i < 4; i++) {
        uint8_t d   = m->delta[i];
        uint8_t in  = wrap26_add(c, d);
        uint8_t out = m->fwd[i][in];
        c = wrap26_sub(out, d);
    }

    c = m->ukw[c];

    for (int i = 3; i >= 0; i--) {
        uint8_t d   = m->delta[i];
        uint8_t in  = wrap26_add(c, d);
        uint8_t out = m->inv[i][in];
        c = wrap26_sub(out, d);
    }

    return m->plugboard[c];
}

size_t enigma_crypt_buffer(EnigmaMachine *m, const char *in, char *out, bool strip_non_alpha) {
    size_t n = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (isalpha(ch)) {
            uint8_t idx = (uint8_t)(toupper(ch) - 'A');
            out[n++] = (char)('A' + enigma_crypt_char(m, idx));
        } else if (!strip_non_alpha) {
            out[n++] = (char)ch;
        }
    }
    out[n] = '\0';
    return n;
}

int enigma_cli_crypt(
    int mode, int r0, int r1, int r2, int r3, int ukw,
    const char *start_str, const char *rings_str, const char *plugs_str,
    const char *in_text, char *out_text
) {
    size_t n = (mode == MODE_M3) ? 3 : 4;
    if (!start_str || !rings_str || !in_text || !out_text) return -1;
    if (strlen(start_str) < n || strlen(rings_str) < n) return -1;

    uint8_t rotors[4] = {(uint8_t)r0, (uint8_t)r1, (uint8_t)r2, (uint8_t)r3};
    uint8_t start[4] = {0}, rings[4] = {0};
    for (size_t i = 0; i < n; i++) {
        start[i] = (uint8_t)(toupper((unsigned char)start_str[i]) - 'A');
        rings[i] = (uint8_t)(toupper((unsigned char)rings_str[i]) - 'A');
    }

    EnigmaMachine m;
    if (!enigma_init(&m, (EnigmaMode)mode, rotors, (uint8_t)ukw, start, rings, plugs_str)) {
        return -2;
    }
    return (int)enigma_crypt_buffer(&m, in_text, out_text, true);
}

int enigma_run_self_tests(bool verbose) {
    EnigmaMachine m;
    char buf[256];
    int failures = 0;

    {
        uint8_t r[3] = {ROTOR_I, ROTOR_II, ROTOR_III};
        uint8_t s[3] = {0, 0, 0}, g[3] = {0, 0, 0};
        enigma_init(&m, MODE_M3, r, UKW_B, s, g, "");
        enigma_crypt_buffer(&m, "AAAAA", buf, true);
        bool ok = (strcmp(buf, "BDZGO") == 0);
        if (verbose) printf("[Test 1] Basic M3 Stepping:  %s (%s)\n", ok ? "PASS" : "FAIL", buf);
        if (!ok) failures++;
    }
    {
        uint8_t r[3] = {ROTOR_I, ROTOR_II, ROTOR_III};
        uint8_t s[3] = {0, 0, 0}, g[3] = {1, 1, 1};
        enigma_init(&m, MODE_M3, r, UKW_B, s, g, "");
        enigma_crypt_buffer(&m, "AAAAA", buf, true);
        bool ok = (strcmp(buf, "EWTYX") == 0);
        if (verbose) printf("[Test 2] Ring Offset Shift:  %s (%s)\n", ok ? "PASS" : "FAIL", buf);
        if (!ok) failures++;
    }
    {
        uint8_t r[3] = {ROTOR_I, ROTOR_II, ROTOR_III};
        uint8_t s[3] = {0, 3, 20}, g[3] = {0, 0, 0};
        enigma_init(&m, MODE_M3, r, UKW_B, s, g, "");
        enigma_step(&m);
        enigma_step(&m);
        enigma_step(&m);
        bool ok = (m.pos[2] == 1 && m.pos[1] == 5 && m.pos[0] == 23);
        if (verbose) printf("[Test 3] Double-Step Carry:  %s (%c%c%c)\n",
                            ok ? "PASS" : "FAIL", 'A'+m.pos[2], 'A'+m.pos[1], 'A'+m.pos[0]);
        if (!ok) failures++;
    }
    {
        EnigmaMachine m3, m4;
        uint8_t r3[3] = {ROTOR_III, ROTOR_I, ROTOR_V}, s3[3] = {12, 4, 25}, g3[3] = {3, 18, 9};
        uint8_t r4[4] = {ROTOR_BETA, ROTOR_III, ROTOR_I, ROTOR_V}, s4[4] = {0, 12, 4, 25}, g4[4] = {0, 3, 18, 9};
        const char *plugs = "AN EZ HK IJ LR MQ OT PV SW UX";
        const char *sample = "WETTERBERICHTVOMSECHSTENMAI";
        char out3[64], out4[64];
        enigma_init(&m3, MODE_M3, r3, UKW_B, s3, g3, plugs);
        enigma_init(&m4, MODE_M4, r4, UKW_B_THIN, s4, g4, plugs);
        enigma_crypt_buffer(&m3, sample, out3, true);
        enigma_crypt_buffer(&m4, sample, out4, true);
        bool ok = (strcmp(out3, out4) == 0);
        if (verbose) printf("[Test 4] 2-in-1 M3/M4 Proof: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }
    {
        uint8_t r[3] = {ROTOR_II, ROTOR_IV, ROTOR_V};
        uint8_t s[3] = {'B'-'A', 'L'-'A', 'A'-'A'}, g[3] = {1, 20, 11};
        const char *ct = "EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT";
        const char *pt = "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERS";
        enigma_init(&m, MODE_M3, r, UKW_B, s, g, "AV BS CG DL FU HZ IN KM OW RX");
        enigma_crypt_buffer(&m, ct, buf, true);
        bool ok = (strcmp(buf, pt) == 0);
        if (verbose) printf("[Test 5] 1941 Barbarossa M3: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }
    {
        uint8_t r[4] = {ROTOR_BETA, ROTOR_II, ROTOR_IV, ROTOR_I};
        uint8_t s[4] = {'V'-'A', 'J'-'A', 'N'-'A', 'A'-'A'}, g[4] = {0, 0, 0, 21};
        const char *ct = "NCZW VUSX PNYM HIAX MNUL";
        const char *pt = "VONVONJLOOKSJHFFTTTE";
        enigma_init(&m, MODE_M4, r, UKW_B_THIN, s, g, "AT BL DF GJ HM NW OP QY RZ VX");
        enigma_crypt_buffer(&m, ct, buf, true);
        bool ok = (strcmp(buf, pt) == 0);
        if (verbose) printf("[Test 6] 1942 U-264 M4:      %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }

    return failures;
}
