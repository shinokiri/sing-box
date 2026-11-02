CC ?= cc
BPF_CLANG ?= clang
BPF_INCLUDES ?= -I/usr/include/$(shell $(CC) -dumpmachine)
CFLAGS ?= -O2 -g

all: snell-tfo-compat

synack.bpf.o: synack.bpf.c compat.h
	$(BPF_CLANG) -target bpfel -O2 -g -Wall -Wextra -Werror $(BPF_INCLUDES) -c $< -o $@

embedded.h: synack.bpf.o embed.py
	python3 embed.py $< $@

snell-tfo-compat: loader.c compat.h embedded.h
	$(CC) $(CFLAGS) -std=gnu11 -Wall -Wextra -Werror -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now -o $@ loader.c -lbpf

clean:
	rm -f snell-tfo-compat synack.bpf.o embedded.h

.PHONY: all clean
