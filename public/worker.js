let wasmReady = false;

self.onmessage = async (e) => {
  const { id, type, payload } = e.data;

  try {
    if (!wasmReady) {
      importScripts("enigma.js");
      await new Promise((resolve) => {
        if (Module.calledRun) resolve();
        else Module.onRuntimeInitialized = resolve;
      });
      wasmReady = true;
    }

    if (type === "RUN_TESTS") {
      const fails = Module.ccall("enigma_run_self_tests", "number", ["number"], [0]);
      self.postMessage({ id, ok: true, result: { failures: fails } });
    } else if (type === "CRYPT") {
      const { mode, rotors, ukw, start, rings, plugs, text } = payload;
      const outPtr = Module._malloc(text.length + 16);
      const len = Module.ccall(
        "enigma_cli_crypt",
        "number",
        ["number", "number", "number", "number", "number", "number", "string", "string", "string", "string", "number"],
        [mode, rotors[0], rotors[1], rotors[2], rotors[3] || 0, ukw, start, rings, plugs, text, outPtr]
      );
      const output = len >= 0 ? Module.UTF8ToString(outPtr) : "";
      Module._free(outPtr);
      self.postMessage({ id, ok: len >= 0, result: { output } });
    } else if (type === "RUN_KRYPTSCRIPT") {
      const { bytecode, ciphertext } = payload;
      const bcPtr = Module._malloc(bytecode.length);
      Module.HEAPU8.set(bytecode, bcPtr);
      const maxJson = 4096;
      const outPtr = Module._malloc(maxJson);

      const rc = Module.ccall(
        "krypt_vm_execute",
        "number",
        ["number", "number", "string", "number", "number"],
        [bcPtr, bytecode.length, ciphertext, outPtr, maxJson]
      );
      const jsonStr = Module.UTF8ToString(outPtr);
      Module._free(bcPtr);
      Module._free(outPtr);

      self.postMessage({ id, ok: rc >= 0, result: JSON.parse(jsonStr) });
    }
  } catch (err) {
    self.postMessage({ id, ok: false, error: err.message });
  }
};
