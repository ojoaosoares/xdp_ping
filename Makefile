CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS ?= -O2 -g -Wall -I./include -I./obj
BPF_CFLAGS ?= -O2 -g -target bpf -I./include

LIBBPF_LIBS ?= -lbpf -lelf -lz

SRC_BPF = src/xdp_ping.bpf.c
OBJ_BPF = obj/xdp_ping.bpf.o
SKEL_H  = include/xdp_ping.skel.h
SRC_USER = src/xdp_ping.c
BIN     = bin/xdp_ping

.PHONY: all clean setup-veth teardown-veth

all: $(BIN)

$(OBJ_BPF): $(SRC_BPF) | obj
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(OBJ_BPF) | include
	$(BPFTOOL) gen skeleton $(OBJ_BPF) name xdp_ping > $(SKEL_H)

$(BIN): $(SRC_USER) $(SKEL_H) | bin
	$(CLANG) $(CFLAGS) $(SRC_USER) -o $(BIN) $(LIBBPF_LIBS)

obj:
	mkdir -p obj

bin:
	mkdir -p bin

include:
	mkdir -p include

clean:
	rm -rf obj bin include/xdp_ping.skel.h

setup-veth:
	@chmod +x scripts/setup_veth.sh
	@sudo ./scripts/setup_veth.sh setup

teardown-veth:
	@chmod +x scripts/setup_veth.sh
	@sudo ./scripts/setup_veth.sh teardown
