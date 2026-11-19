// KryptScript DSL -> Bytecode Compiler for krypt_vm.c
const ROTOR_BITS = {
  I: 1, II: 2, III: 4, IV: 8, V: 16, VI: 32, VII: 64, VIII: 128
};
const GREEK_BITS = { BETA: 1, GAMMA: 2 };
const UKW_BITS = { B: 1, C: 2, "B-THIN": 4, "C-THIN": 8 };

export function compileKryptScript(source) {
  const bytes = [];
  const lines = source.split(/\r?\n/);

  for (let rawLine of lines) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;

    // MODE M3 | M4
    let m = line.match(/^MODE\s+(M3|M4)$/i);
    if (m) {
      bytes.push(0x01, m[1].toUpperCase() === "M4" ? 1 : 0);
      continue;
    }

    // CRIB "WETTER" AT 0..25 WEIGHT 15.0
    m = line.match(/^CRIB\s+"([A-Za-z]+)"\s+AT\s+(\d+)\.\.(\d+)\s+WEIGHT\s+([\d.]+)$/i);
    if (m) {
      const word = m[1].toUpperCase();
      const pMin = Math.min(255, parseInt(m[2], 10));
      const pMax = Math.min(255, parseInt(m[3], 10));
      const w10  = Math.min(255, Math.round(parseFloat(m[4]) * 10));
      bytes.push(0x02, pMin, pMax, w10, word.length);
      for (let i = 0; i < word.length; i++) {
        bytes.push(word.charCodeAt(i) - 65);
      }
      continue;
    }

    // MUTATE DELETE 3 PENALTY 8.5
    m = line.match(/^MUTATE\s+DELETE\s+(\d+)\s+PENALTY\s+([\d.]+)$/i);
    if (m) {
      const idx = Math.min(255, parseInt(m[1], 10));
      const p10 = Math.min(255, Math.round(parseFloat(m[2]) * 10));
      bytes.push(0x03, idx, p10);
      continue;
    }

    // STAGE 1: SWEEP GREEK [BETA] ROTORS [I,II,III,IV,V] UKW [B] KEEP 16
    m = line.match(/^STAGE\s+1:\s+SWEEP(?:\s+GREEK\s+\[([^\]]+)\])?\s+ROTORS\s+\[([^\]]+)\]\s+UKW\s+\[([^\]]+)\]\s+KEEP\s+(\d+)$/i);
    if (m) {
      let gMask = 0x03;
      if (m[1]) {
        gMask = 0;
        for (const tok of m[1].split(",")) {
          const k = tok.trim().toUpperCase();
          if (GREEK_BITS[k]) gMask |= GREEK_BITS[k];
        }
      }
      let rMask = 0;
      for (const tok of m[2].split(",")) {
        const k = tok.trim().toUpperCase();
        if (ROTOR_BITS[k]) rMask |= ROTOR_BITS[k];
      }
      let uMask = 0;
      for (const tok of m[3].split(",")) {
        const k = tok.trim().toUpperCase();
        if (UKW_BITS[k]) uMask |= UKW_BITS[k];
      }
      const keep = Math.min(64, parseInt(m[4], 10));
      bytes.push(0x04, gMask, rMask, uMask, keep);
      continue;
    }

    // STAGE 2: TUNE RINGS KEEP 8
    m = line.match(/^STAGE\s+2:\s+TUNE\s+RINGS\s+KEEP\s+(\d+)$/i);
    if (m) {
      bytes.push(0x05, Math.min(64, parseInt(m[1], 10)));
      continue;
    }

    // STAGE 3: CLIMB PLUGS ITER 1000
    m = line.match(/^STAGE\s+3:\s+CLIMB\s+PLUGS\s+ITER\s+(\d+)$/i);
    if (m) {
      const iters = Math.min(65535, parseInt(m[1], 10));
      bytes.push(0x06, (iters >> 8) & 0xff, iters & 0xff);
      continue;
    }

    throw new Error(`KryptScript syntax error: "${line}"`);
  }

  bytes.push(0x00); // OP_HALT
  return new Uint8Array(bytes);
}
