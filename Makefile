CC      = gcc
CFLAGS  = -O3 -std=c99 -Wall -Wextra -fPIC
EMCC    = emcc

SRC     = src/enigma_core.c src/krypt_vm.c

all: native

native: src/main.c $(SRC) src/enigma_core.h src/krypt_vm.h
	$(CC) $(CFLAGS) src/main.c $(SRC) -o sim_enigma

lib: $(SRC) src/enigma_core.h src/krypt_vm.h
	$(CC) $(CFLAGS) -shared $(SRC) -o libenigma.so

wasm: $(SRC) src/enigma_core.h src/krypt_vm.h
	$(EMCC) $(SRC) -O3 \
		-s WASM=1 \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s EXPORTED_FUNCTIONS='["_enigma_cli_crypt","_enigma_run_self_tests","_krypt_vm_execute","_malloc","_free"]' \
		-s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","HEAPU8"]' \
		-o public/enigma.js

test: native
	./sim_enigma --test

clean:
	rm -f sim_enigma libenigma.so public/enigma.js public/enigma.wasm
