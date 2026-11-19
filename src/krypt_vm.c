#include "krypt_vm.h"
#include "enigma_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_CT_LEN      512
#define MAX_CANDIDATES  64
#define MAX_CRIBS       8

typedef struct {
    uint8_t pos_min;
    uint8_t pos_max;
    double  weight;
    uint8_t len;
    uint8_t word[32];
} CribRule;

typedef struct {
    EnigmaMode mode;
    uint8_t rotors_lr[4]; // [0..2] for M3; [0..3] for M4
    uint8_t ukw_id;
    uint8_t delta0[4];    // Initial offset (pos[0] - ring[0]) mod 26
    uint8_t rings_lr[4];
    uint8_t plugs[26];
    double  ic;
    double  score;
} KeyCandidate;

// German single-letter log-weight table (A..Z, higher = more frequent in German)
static const int8_t DE_MONO[26] = {
    6, 2, 3, 5, 17, 2, 3, 5, 8, 0, 1, 3, 3,
    10, 3, 1, 0, 7, 7, 6, 4, 1, 2, 1, 0, 1
};

// High-value German bigrams (packed as (c1 << 5) | c2)
static double score_german_text(const uint8_t *pt, size_t len, const CribRule *cribs, int n_cribs) {
    if (len < 4) return -1e9;
    double score = 0.0;

    for (size_t i = 0; i < len; i++) {
        score += (double)DE_MONO[pt[i]] * 0.35;
    }

    for (size_t i = 0; i + 1 < len; i++) {
        uint8_t a = pt[i], b = pt[i + 1];
        // Common German bigrams: ER, EN, CH, DE, EI, ND, TE, IN, IE, GE, ES, NE, UN, ST, SCH
        if ((a == 4  && b == 17) || // ER
            (a == 4  && b == 13) || // EN
            (a == 2  && b == 7)  || // CH
            (a == 3  && b == 4)  || // DE
            (a == 4  && b == 8)  || // EI
            (a == 13 && b == 3)  || // ND
            (a == 19 && b == 4)  || // TE
            (a == 8  && b == 13) || // IN
            (a == 8  && b == 4)  || // IE
            (a == 6  && b == 4)  || // GE
            (a == 20 && b == 13) || // UN
            (a == 18 && b == 19)) { // ST
            score += 2.2;
        }
        // Penalize illegal/rare German bigrams (QQ, JJ, YX, Q without U)
        if (a == 16 && b != 20) score -= 3.5;
        if (a == b && (a == 9 || a == 16 || a == 23 || a == 24)) score -= 4.0;
    }

    for (size_t i = 0; i + 2 < len; i++) {
        uint8_t a = pt[i], b = pt[i + 1], c = pt[i + 2];
        if ((a == 18 && b == 2  && c == 7)  || // SCH
            (a == 4  && b == 8  && c == 13) || // EIN
            (a == 8  && b == 2  && c == 7)  || // ICH
            (a == 20 && b == 13 && c == 3)  || // UND
            (a == 3  && b == 4  && c == 17) || // DER
            (a == 3  && b == 8  && c == 4)  || // DIE
            (a == 20 && b == 13 && c == 6)) {  // UNG
            score += 4.5;
        }
    }

    // Apply REA Crib constraints
    for (int k = 0; k < n_cribs; k++) {
        const CribRule *cr = &cribs[k];
        if (cr->len > len) continue;
        size_t max_p = (cr->pos_max + cr->len <= len) ? cr->pos_max : (len - cr->len);
        for (size_t p = cr->pos_min; p <= max_p; p++) {
            size_t matches = 0;
            for (size_t j = 0; j < cr->len; j++) {
                if (pt[p + j] == cr->word[j]) matches++;
            }
            if (matches == cr->len) {
                score += cr->weight * (double)cr->len;
                break;
            }
        }
    }

    return score;
}

static double compute_ic(const uint8_t *buf, size_t len) {
    if (len < 2) return 0.0;
    uint16_t counts[26] = {0};
    for (size_t i = 0; i < len; i++) counts[buf[i]]++;
    uint32_t num = 0;
    for (int c = 0; c < 26; c++) {
        num += (uint32_t)counts[c] * (uint32_t)(counts[c] > 0 ? counts[c] - 1 : 0);
    }
    return (double)num / (double)(len * (len - 1));
}

static void decrypt_with_candidate(const KeyCandidate *cand, const uint8_t *ct, size_t len, uint8_t *pt) {
    EnigmaMachine m;
    size_t n_wheels = (cand->mode == MODE_M3) ? 3 : 4;
    uint8_t start_lr[4] = {0};
    for (size_t i = 0; i < n_wheels; i++) {
        start_lr[i] = (uint8_t)((cand->delta0[i] + cand->rings_lr[i]) % 26);
    }
    enigma_init(&m, cand->mode, cand->rotors_lr, cand->ukw_id, start_lr, cand->rings_lr, NULL);
    memcpy(m.plugboard, cand->plugs, 26);

    for (size_t i = 0; i < len; i++) {
        pt[i] = enigma_crypt_char(&m, ct[i]);
    }
}

static void insert_top_candidate(KeyCandidate *list, int *count, int max_keep, const KeyCandidate *cand) {
    int pos = *count;
    while (pos > 0 && cand->score > list[pos - 1].score) {
        if (pos < max_keep) list[pos] = list[pos - 1];
        pos--;
    }
    if (pos < max_keep) {
        list[pos] = *cand;
        if (*count < max_keep) (*count)++;
    }
}

static const char *rotor_name(uint8_t id) {
    static const char *names[ROTOR_COUNT] = {
        "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "Beta", "Gamma"
    };
    return (id < ROTOR_COUNT) ? names[id] : "?";
}

static const char *ukw_name(uint8_t id) {
    static const char *names[UKW_COUNT] = {"B", "C", "B-thin", "C-thin"};
    return (id < UKW_COUNT) ? names[id] : "?";
}

int krypt_vm_execute(
    const uint8_t *bytecode,
    size_t bc_len,
    const char *ciphertext,
    char *json_report_out,
    size_t max_out_len
) {
    if (!bytecode || !ciphertext || !json_report_out || max_out_len < 256) return -1;

    uint8_t raw_ct[MAX_CT_LEN];
    size_t raw_len = 0;
    for (size_t i = 0; ciphertext[i] && raw_len < MAX_CT_LEN - 1; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            raw_ct[raw_len++] = (uint8_t)(toupper((unsigned char)ciphertext[i]) - 'A');
        }
    }
    if (raw_len < 4) return -2;

    EnigmaMode mode = MODE_M3;
    CribRule cribs[MAX_CRIBS];
    int n_cribs = 0;
    int drop_idx = -1;
    double edit_penalty = 0.0;

    KeyCandidate cands[MAX_CANDIDATES];
    int n_cands = 0;
    uint8_t pt_buf[MAX_CT_LEN];

    size_t pc = 0;
    while (pc < bc_len) {
        uint8_t op = bytecode[pc++];
        if (op == OP_HALT) break;

        if (op == OP_SET_MODE && pc < bc_len) {
            mode = (bytecode[pc++] == 1) ? MODE_M4 : MODE_M3;
        } else if (op == OP_SET_CRIB && pc + 4 <= bc_len) {
            uint8_t pmin = bytecode[pc++];
            uint8_t pmax = bytecode[pc++];
            double w     = (double)bytecode[pc++] / 10.0;
            uint8_t clen = bytecode[pc++];
            if (pc + clen <= bc_len && n_cribs < MAX_CRIBS && clen < 32) {
                cribs[n_cribs].pos_min = pmin;
                cribs[n_cribs].pos_max = pmax;
                cribs[n_cribs].weight  = w;
                cribs[n_cribs].len     = clen;
                memcpy(cribs[n_cribs].word, &bytecode[pc], clen);
                n_cribs++;
            }
            pc += clen;
        } else if (op == OP_SET_EDIT_DROP && pc + 2 <= bc_len) {
            drop_idx = (int)bytecode[pc++];
            edit_penalty = (double)bytecode[pc++] / 10.0;
        } else if (op == OP_SWEEP_IC && pc + 4 <= bc_len) {
            uint8_t greek_mask = bytecode[pc++];
            uint8_t rotor_mask = bytecode[pc++];
            uint8_t ukw_mask   = bytecode[pc++];
            int keep_top       = bytecode[pc++];
            if (keep_top > MAX_CANDIDATES) keep_top = MAX_CANDIDATES;

            // Prepare active ciphertext (applying optional single-char deletion hypothesis)
            uint8_t active_ct[MAX_CT_LEN];
            size_t len = 0;
            for (size_t i = 0; i < raw_len; i++) {
                if ((int)i == drop_idx) continue;
                active_ct[len++] = raw_ct[i];
            }

            n_cands = 0;
            int g_start = (mode == MODE_M3) ? 0 : 0;
            int g_end   = (mode == MODE_M3) ? 1 : 2;

            for (int g = g_start; g < g_end; g++) {
                if (mode == MODE_M4 && !(greek_mask & (1u << g))) continue;
                uint8_t greek_id = (g == 0) ? ROTOR_BETA : ROTOR_GAMMA;

                for (uint8_t u = 0; u < UKW_COUNT; u++) {
                    if (!(ukw_mask & (1u << u))) continue;

                    for (uint8_t rL = 0; rL < 8; rL++) {
                        if (!(rotor_mask & (1u << rL))) continue;
                        for (uint8_t rM = 0; rM < 8; rM++) {
                            if (rM == rL || !(rotor_mask & (1u << rM))) continue;
                            for (uint8_t rR = 0; rR < 8; rR++) {
                                if (rR == rL || rR == rM || !(rotor_mask & (1u << rR))) continue;

                                uint8_t gp_max = (mode == MODE_M3) ? 1 : 26;
                                for (uint8_t gp = 0; gp < gp_max; gp++) {
                                    for (uint8_t pL = 0; pL < 26; pL++) {
                                        for (uint8_t pM = 0; pM < 26; pM++) {
                                            for (uint8_t pR = 0; pR < 26; pR++) {
                                                KeyCandidate cand;
                                                memset(&cand, 0, sizeof(cand));
                                                cand.mode   = mode;
                                                cand.ukw_id = u;
                                                for (uint8_t k = 0; k < 26; k++) cand.plugs[k] = k;

                                                if (mode == MODE_M3) {
                                                    cand.rotors_lr[0] = rL; cand.rotors_lr[1] = rM; cand.rotors_lr[2] = rR;
                                                    cand.delta0[0] = pL; cand.delta0[1] = pM; cand.delta0[2] = pR;
                                                } else {
                                                    cand.rotors_lr[0] = greek_id; cand.rotors_lr[1] = rL;
                                                    cand.rotors_lr[2] = rM;       cand.rotors_lr[3] = rR;
                                                    cand.delta0[0] = gp; cand.delta0[1] = pL;
                                                    cand.delta0[2] = pM; cand.delta0[3] = pR;
                                                }

                                                decrypt_with_candidate(&cand, active_ct, len, pt_buf);
                                                cand.ic = compute_ic(pt_buf, len);
                                                cand.score = cand.ic * 1000.0;
                                                insert_top_candidate(cands, &n_cands, keep_top, &cand);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (op == OP_TUNE_RINGS && pc < bc_len) {
            int keep_top = bytecode[pc++];
            if (keep_top > n_cands) keep_top = n_cands;

            uint8_t active_ct[MAX_CT_LEN];
            size_t len = 0;
            for (size_t i = 0; i < raw_len; i++) {
                if ((int)i == drop_idx) continue;
                active_ct[len++] = raw_ct[i];
            }

            int rM_idx = (mode == MODE_M3) ? 1 : 2;
            int rR_idx = (mode == MODE_M3) ? 2 : 3;

            for (int c = 0; c < n_cands; c++) {
                KeyCandidate best = cands[c];
                best.score = -1e9;
                for (uint8_t rm = 0; rm < 26; rm++) {
                    for (uint8_t rr = 0; rr < 26; rr++) {
                        KeyCandidate trial = cands[c];
                        trial.rings_lr[rM_idx] = rm;
                        trial.rings_lr[rR_idx] = rr;
                        decrypt_with_candidate(&trial, active_ct, len, pt_buf);
                        double s = score_german_text(pt_buf, len, cribs, n_cribs);
                        if (s > best.score) {
                            best = trial;
                            best.score = s;
                        }
                    }
                }
                cands[c] = best;
            }
            n_cands = keep_top;
        } else if (op == OP_CLIMB_PLUGS && pc + 2 <= bc_len) {
            int max_iters = ((int)bytecode[pc] << 8) | (int)bytecode[pc + 1];
            pc += 2;

            uint8_t active_ct[MAX_CT_LEN];
            size_t len = 0;
            for (size_t i = 0; i < raw_len; i++) {
                if ((int)i == drop_idx) continue;
                active_ct[len++] = raw_ct[i];
            }

            for (int c = 0; c < n_cands; c++) {
                decrypt_with_candidate(&cands[c], active_ct, len, pt_buf);
                cands[c].score = score_german_text(pt_buf, len, cribs, n_cribs) - edit_penalty;

                for (int iter = 0; iter < max_iters; iter++) {
                    bool improved = false;
                    uint8_t best_a = 0, best_b = 0;

                    for (uint8_t a = 0; a < 25; a++) {
                        if (cands[c].plugs[a] != a) continue;
                        for (uint8_t b = a + 1; b < 26; b++) {
                            if (cands[c].plugs[b] != b) continue;

                            cands[c].plugs[a] = b;
                            cands[c].plugs[b] = a;
                            decrypt_with_candidate(&cands[c], active_ct, len, pt_buf);
                            double s = score_german_text(pt_buf, len, cribs, n_cribs) - edit_penalty;

                            if (s > cands[c].score + 1e-6) {
                                cands[c].score = s;
                                best_a = a;
                                best_b = b;
                                improved = true;
                            }
                            cands[c].plugs[a] = a;
                            cands[c].plugs[b] = b;
                        }
                    }
                    if (!improved) break;
                    cands[c].plugs[best_a] = best_b;
                    cands[c].plugs[best_b] = best_a;
                }
            }
        } else {
            break;
        }
    }

    // Format top candidate into JSON report
    if (n_cands == 0) {
        snprintf(json_report_out, max_out_len, "{\"status\":\"empty\",\"candidates\":[]}");
        return 0;
    }

    // Pick highest scoring candidate after plugboard climb
    int best_idx = 0;
    for (int i = 1; i < n_cands; i++) {
        if (cands[i].score > cands[best_idx].score) best_idx = i;
    }
    KeyCandidate *top = &cands[best_idx];

    uint8_t active_ct[MAX_CT_LEN];
    size_t len = 0;
    for (size_t i = 0; i < raw_len; i++) {
        if ((int)i == drop_idx) continue;
        active_ct[len++] = raw_ct[i];
    }
    decrypt_with_candidate(top, active_ct, len, pt_buf);

    char pt_str[MAX_CT_LEN];
    for (size_t i = 0; i < len; i++) pt_str[i] = (char)('A' + pt_buf[i]);
    pt_str[len] = '\0';

    char plugs_str[64] = {0};
    size_t ppos = 0;
    for (uint8_t a = 0; a < 26; a++) {
        if (top->plugs[a] > a && ppos + 4 < sizeof(plugs_str)) {
            if (ppos > 0) plugs_str[ppos++] = ' ';
            plugs_str[ppos++] = (char)('A' + a);
            plugs_str[ppos++] = (char)('A' + top->plugs[a]);
        }
    }

    size_t nw = (top->mode == MODE_M3) ? 3 : 4;
    char start_str[8] = {0}, rings_str[8] = {0};
    for (size_t i = 0; i < nw; i++) {
        start_str[i] = (char)('A' + ((top->delta0[i] + top->rings_lr[i]) % 26));
        rings_str[i] = (char)('A' + top->rings_lr[i]);
    }

    if (top->mode == MODE_M3) {
        snprintf(json_report_out, max_out_len,
            "{\"status\":\"ok\",\"mode\":\"M3\",\"score\":%.2f,\"ic\":%.5f,"
            "\"rotors\":\"%s-%s-%s\",\"ukw\":\"%s\",\"start\":\"%s\",\"rings\":\"%s\","
            "\"plugs\":\"%s\",\"plaintext\":\"%s\"}",
            top->score, top->ic,
            rotor_name(top->rotors_lr[0]), rotor_name(top->rotors_lr[1]), rotor_name(top->rotors_lr[2]),
            ukw_name(top->ukw_id), start_str, rings_str, plugs_str, pt_str
        );
    } else {
        snprintf(json_report_out, max_out_len,
            "{\"status\":\"ok\",\"mode\":\"M4\",\"score\":%.2f,\"ic\":%.5f,"
            "\"rotors\":\"%s-%s-%s-%s\",\"ukw\":\"%s\",\"start\":\"%s\",\"rings\":\"%s\","
            "\"plugs\":\"%s\",\"plaintext\":\"%s\"}",
            top->score, top->ic,
            rotor_name(top->rotors_lr[0]), rotor_name(top->rotors_lr[1]),
            rotor_name(top->rotors_lr[2]), rotor_name(top->rotors_lr[3]),
            ukw_name(top->ukw_id), start_str, rings_str, plugs_str, pt_str
        );
    }

    return 1;
}
