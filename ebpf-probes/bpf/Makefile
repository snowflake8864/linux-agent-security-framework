# Makefile for eBPF programs
# Can be run on ARM or x86 machines without Rust environment.

CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Detect architecture for defines
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	DEFAULT_ARCH := x86
	DEFAULT_ARCH_DEFINE := __TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
	DEFAULT_ARCH := arm64
	DEFAULT_ARCH_DEFINE := __TARGET_ARCH_arm64
else
	DEFAULT_ARCH := x86
	DEFAULT_ARCH_DEFINE := __TARGET_ARCH_x86
endif

# Allow manual override: make ARCH=arm64
ARCH ?= $(DEFAULT_ARCH)
ifeq ($(ARCH),arm64)
	ARCH_DEFINE := __TARGET_ARCH_arm64
else
	ARCH_DEFINE := __TARGET_ARCH_x86
endif

CFLAGS := -target bpf -D$(ARCH_DEFINE) -I. -O2 -g -c

# Output directory for BPF objects (matches xtask behavior)
BPF_OUT_DIR := ../../bpf

# Source files
SOURCES := agent.bpf.c tc_pkt_mod.bpf.c xdp_pkt_mod.bpf.c forward.bpf.c unified_agent.bpf.c
OBJECTS := $(addprefix $(BPF_OUT_DIR)/, $(SOURCES:.c=.o))

.PHONY: all clean help

all: $(OBJECTS)
	@echo "✓ eBPF objects built successfully for $(ARCH) in $(BPF_OUT_DIR)/"

$(BPF_OUT_DIR)/%.o: %.c vmlinux.h
	@mkdir -p $(BPF_OUT_DIR)
	@echo "Building BPF: $< -> $@"
	$(CLANG) $(CFLAGS) $< -o $@
	# $(LLVM_STRIP)  $@ # Optional: strip debug info if needed

clean:
	rm -f $(OBJECTS)
	@echo "✓ Cleaned BPF objects"

help:
	@echo "Usage:"
	@echo "  make             - Build for current architecture ($(UNAME_M))"
	@echo "  make ARCH=x86    - Build for x86_64"
	@echo "  make ARCH=arm64  - Build for ARM64"
	@echo "  make clean       - Remove built objects"
