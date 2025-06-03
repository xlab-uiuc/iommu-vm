CC = gcc
CLANG = clang
BPFTOOL = bpftool
BPF_TARGET_ARCH = bpf

COMMON_BPF_DEPS = vmlinux.h tracing_utils.h Makefile
LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS = $(shell pkg-config --libs libbpf)

CFLAGS_BPF = -g -O2 \
		-target $(BPF_TARGET_ARCH) \
		-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
		-I. \
		$(LIBBPF_CFLAGS) \
		-I/usr/include \
		-I/usr/include/$(shell uname -m)-linux-gnu

CFLAGS_USER = -g -Wall -I.
LDFLAGS_USER := $(LIBBPF_LIBS) -lelf -lz

# BPF‐related sources and objects
HOST_BPF_SRC = host_qemu_tracer.bpf.c
HOST_BPF_OBJ = $(HOST_BPF_SRC:.bpf.c=.bpf.o)
HOST_BPF_SKEL = $(HOST_BPF_SRC:.bpf.c=.skel.h)

GUEST_BPF_SRC = guest_tracer.bpf.c
GUEST_BPF_OBJ = $(GUEST_BPF_SRC:.bpf.c=.bpf.o)
GUEST_BPF_SKEL = $(GUEST_BPF_SRC:.bpf.c=.skel.h)

READER_SRC = reader.c
READER_APP = reader
HOST_LOADER_SRC = host_qemu_loader.c
HOST_LOADER_APP = host_loader
GUEST_LOADER_SRC = guest_loader.c
GUEST_LOADER_APP = guest_loader


LDFLAGS_COMMON = -lelf -lz
LDFLAGS_LOADER = $(LIBBPF_LIBS) $(LDFLAGS_COMMON)

.PHONY: all clean host guest reader
all: host guest reader

vmlinux.h:
	@echo "Generating vmlinux.h via bpftool..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@ \
		|| (echo "Failed to generate vmlinux.h. Is /sys/kernel/btf/vmlinux available and bpftool installed?" && false)


$(HOST_BPF_OBJ): $(HOST_BPF_SRC) $(COMMON_BPF_DEPS)
	@echo "Compiling $< → $@"
	@$(CLANG) $(CFLAGS_BPF) -c $(HOST_BPF_SRC) -o $@

$(HOST_BPF_SKEL): $(HOST_BPF_OBJ)
	@echo "Generating skeleton for $< → $@"
	@$(BPFTOOL) gen skeleton $(HOST_BPF_OBJ) > $@

$(HOST_LOADER_APP): $(HOST_LOADER_SRC) $(HOST_BPF_SKEL) tracing_utils.h Makefile
	@echo "Linking host loader: $@"
	@$(CC) $(CFLAGS_USER) $(HOST_LOADER_SRC) $(HOST_BPF_SKEL) $(LDFLAGS_USER) -o $@

host: $(HOST_LOADER_APP)

$(GUEST_BPF_OBJ): $(GUEST_BPF_SRC) $(COMMON_BPF_DEPS)
	@echo "Compiling $< → $@"
	@$(CLANG) $(CFLAGS_BPF) -c $(GUEST_BPF_SRC) -o $@

$(GUEST_BPF_SKEL): $(GUEST_BPF_OBJ)
	@echo "Generating skeleton for $< → $@"
	@$(BPFTOOL) gen skeleton $(GUEST_BPF_OBJ) > $@

$(GUEST_LOADER_APP): $(GUEST_LOADER_SRC) $(GUEST_BPF_SKEL) tracing_utils.h Makefile
	@echo "Linking guest loader: $@"
	@$(CC) $(CFLAGS_USER) $(GUEST_LOADER_SRC) $(GUEST_BPF_SKEL) $(LDFLAGS_USER) -o $@

guest: $(GUEST_LOADER_APP)

$(READER_APP): $(READER_SRC) tracing_utils.h Makefile
	@echo "Building reader: $@"
	@$(CC) $(CFLAGS_USER) $(READER_SRC) -o $@

reader: $(READER_APP)

# --- Clean up ---
clean:
	@echo "Cleaning up generated files..."
	@rm -f $(HOST_BPF_OBJ) $(HOST_BPF_SKEL) \
	       $(GUEST_BPF_OBJ) $(GUEST_BPF_SKEL) \
	       $(HOST_LOADER_APP) $(GUEST_LOADER_APP) \
	       $(READER_APP) \
	       vmlinux.h

