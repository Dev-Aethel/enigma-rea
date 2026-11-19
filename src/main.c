#include "enigma_core.h"
#include "krypt_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static bool ascii_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

static int parse_rotor(const char *s) {
    if (strcmp(s, "I") == 0)     return ROTOR_I;
    if (strcmp(s, "II") == 0)    return ROTOR_II;
    if (strcmp(s, "III") == 0)   return ROTOR_III;
    if (strcmp(s, "IV") == 0)    return ROTOR_IV;
    if (strcmp(s, "V") == 0)     return ROTOR_V;
    if (strcmp(s, "VI") == 0)    return ROTOR_VI;
    if (strcmp(s, "VII") == 0)   return ROTOR_VII;
    if (strcmp(s, "VIII") == 0)  return ROTOR_VIII;
    if (ascii_ieq(s, "Beta"))    return ROTOR_BETA;
    if (ascii_ieq(s, "Gamma"))   return ROTOR_GAMMA;
    return -1;
}

static int parse_ukw(const char *s) {
    if (ascii_ieq(s, "B"))      return UKW_B;
    if (ascii_ieq(s, "C"))      return UKW_C;
    if (ascii_ieq(s, "B-thin")) return UKW_B_THIN;
    if (ascii_ieq(s, "C-thin")) return UKW_C_THIN;
    return -1;
}

static bool parse_alpha_vec(const char *s, uint8_t out[], size_t expected) {
    if (strlen(s) != expected) return false;
    for (size_t i = 0; i < expected; i++) {
        if (!isalpha((unsigned char)s[i])) return false;
        out[i] = (uint8_t)(toupper((unsigned char)s[i]) - 'A');
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--test") == 0)) {
        return (enigma_run_self_tests(true) == 0) ? 0 : 1;
    }

    EnigmaMode mode = MODE_M4;
    const char *rotors_str = "Beta,II,IV,I";
    const char *ukw_str    = "B-thin";
    const char *rings_str  = "AAAV";
    const char *start_str  = "VJNA";
    const char *plugs_str  = "";
    const char *text_str   = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = ascii_ieq(argv[++i], "m3") ? MODE_M3 : MODE_M4;
        } else if (strcmp(argv[i], "--rotors") == 0 && i + 1 < argc) {
            rotors_str = argv[++i];
        } else if (strcmp(argv[i], "--ukw") == 0 && i + 1 < argc) {
            ukw_str = argv[++i];
        } else if (strcmp(argv[i], "--rings") == 0 && i + 1 < argc) {
            rings_str = argv[++i];
        } else if (strcmp(argv[i], "--start") == 0 && i + 1 < argc) {
            start_str = argv[++i];
        } else if (strcmp(argv[i], "--plugs") == 0 && i + 1 < argc) {
            plugs_str = argv[++i];
        } else if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) {
            text_str = argv[++i];
        }
    }

    if (!text_str) {
        fprintf(stderr, "Usage: %s --test | --mode <m3|m4> --rotors <R1,R2,...> --ukw <B|C|B-thin|C-thin> --rings <ABC[D]> --start <ABC[D]> [--plugs \"AB CD\"] --text <MSG>\n", argv[0]);
        return 1;
    }

    size_t n_wheels = (mode == MODE_M3) ? 3 : 4;
    uint8_t rotors[4] = {0}, start[4] = {0}, rings[4] = {0};
    char rcopy[64];
    strncpy(rcopy, rotors_str, sizeof(rcopy) - 1);
    rcopy[sizeof(rcopy) - 1] = '\0';

    size_t count = 0;
    char *tok = strtok(rcopy, ",");
    while (tok && count < 4) {
        int id = parse_rotor(tok);
        if (id < 0) { fprintf(stderr, "Invalid rotor: %s\n", tok); return 1; }
        rotors[count++] = (uint8_t)id;
        tok = strtok(NULL, ",");
    }

    int ukw_id = parse_ukw(ukw_str);
    if (count != n_wheels || ukw_id < 0 ||
        !parse_alpha_vec(start_str, start, n_wheels) ||
        !parse_alpha_vec(rings_str, rings, n_wheels)) {
        fprintf(stderr, "Invalid key dimensions or reflector.\n");
        return 1;
    }

    EnigmaMachine m;
    if (!enigma_init(&m, mode, rotors, (uint8_t)ukw_id, start, rings, plugs_str)) {
        fprintf(stderr, "Invalid plugboard configuration.\n");
        return 1;
    }

    char *out = malloc(strlen(text_str) + 1);
    if (!out) return 1;
    enigma_crypt_buffer(&m, text_str, out, true);
    printf("%s\n", out);
    free(out);
    return 0;
}
