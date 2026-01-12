# Phantom Mesh "ULTIMATE" Build System
# Optimization: Size (z), LTO (Fat), Strip (Symbols + Sections)
# Obfuscation: Path Remapping, Metadata Removal
# Architecture: Polyglot (Linux, Windows, macOS)

# --- Configuration ---
CARGO := cargo
OUT_DIR := dist
PHANTOM_BIN := phantom
MESH_BIN := phantom_mesh
PWD := $(shell pwd)

# --- Compiler Flags (The "Secret Sauce") ---
# 1. Basic Optimizations
# FLAGS_OPT := -C opt-level=z -C lto=fat -C codegen-units=1 -C panic=abort -C embed-bitcode=yes 
FLAGS_OPT := # Rely on Cargo.toml for optimization to avoid proc-macro LTO issues 

# 2. Low-Level Control
# - force-frame-pointers=no: Save registers, smaller stack frames
# - relocation-model=static: No PIC overhead for executables (Linux only usually, but good to try)
FLAGS_LOW := -C force-frame-pointers=no

# 3. Obfuscation & Anonymity
# - strip=symbols: Remove all debug symbols
# - remap-path-prefix: CRITICAL. Hides "/Users/zvwgvx/..." => "/src". 防止 lộ đường dẫn máy dev.
FLAGS_OBF := -C strip=symbols \
             --remap-path-prefix $(PWD)=/void \
             --remap-path-prefix $(HOME)=/root \
             --remap-path-prefix .rustup=/stdlib

# Combined Flags
RUSTFLAGS_COMMON := $(FLAGS_OPT) $(FLAGS_LOW) $(FLAGS_OBF)

# Post-Processing Tools
STRIP_LINUX := strip --strip-all --remove-section=.comment --remove-section=.note
STRIP_MAC := strip -x
UPX := upx --best --lzma

# --- Targets ---
.PHONY: all setup clean phantom mesh_local mesh_linux mesh_windows help compress

# Build native binaries for the current Host OS (Guaranteed to work)
all: setup phantom mesh_macos_arm64 mesh_linux_amd64 mesh_linux_arm64 mesh_windows_amd64
	@echo "\n[✓] ALL BUILDS COMPLETE. Artifacts in 'dist/'"
	@echo "[!] Note: Targets follow naming convention: {module}_{os}_{arch}"

setup:
	@mkdir -p $(OUT_DIR)

# 1. Phantom Node (Host/macOS)
phantom:
	@echo "\n[*] Building Phantom Node (Master)..."
	@RUSTFLAGS="$(RUSTFLAGS_COMMON)" $(CARGO) build --release -p $(PHANTOM_BIN)
	@cp target/release/$(PHANTOM_BIN) $(OUT_DIR)/phantom
	@$(STRIP_MAC) $(OUT_DIR)/phantom 2>/dev/null || echo "[!] Strip failed (ignore if signed)"
	@echo "[+] Artifact: $(OUT_DIR)/phantom"

# 2. Mesh Node (macOS ARM64 / Host)
# Target: Host Native (arm64)
mesh_macos_arm64: setup
	@echo "\n[*] Building Mesh Node (macOS ARM64)..."
	@RUSTFLAGS="$(RUSTFLAGS_COMMON)" $(CARGO) build --release -p $(MESH_BIN)
	@cp target/release/$(MESH_BIN) $(OUT_DIR)/mesh_macos_arm64
	@$(STRIP_MAC) $(OUT_DIR)/mesh_macos_arm64 2>/dev/null || echo "[!] Strip failed"
	@echo "[+] Artifact: $(OUT_DIR)/mesh_macos_arm64"

# 3. Mesh Node (Linux AMD64 / x64)
# Target: x86_64-unknown-linux-musl
mesh_linux_amd64: setup
	@echo "\n[*] Building Mesh Node (Linux AMD64 - Static/MUSL)..."
	@RUSTFLAGS="$(RUSTFLAGS_COMMON) -C target-feature=+crt-static" \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc \
	CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc \
	CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++ \
	AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar \
	$(CARGO) build --release --target x86_64-unknown-linux-musl -p $(MESH_BIN) && \
	cp target/x86_64-unknown-linux-musl/release/$(MESH_BIN) $(OUT_DIR)/mesh_linux_amd64 && \
	echo "[*] Stripping metadata..." && \
	($(STRIP_LINUX) $(OUT_DIR)/mesh_linux_amd64 2>/dev/null || strip $(OUT_DIR)/mesh_linux_amd64) && \
	echo "[+] Artifact: $(OUT_DIR)/mesh_linux_amd64"

# 4. Mesh Node (Linux ARM64 / Raspberry Pi)
# Target: aarch64-unknown-linux-musl
mesh_linux_arm64: setup
	@echo "\n[*] Building Mesh Node (Linux ARM64 - Raspberry Pi)..."
	@RUSTFLAGS="$(RUSTFLAGS_COMMON) -C target-feature=+crt-static" \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
	CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc \
	CXX_aarch64_unknown_linux_musl=aarch64-linux-musl-g++ \
	AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar \
	$(CARGO) build --release --target aarch64-unknown-linux-musl -p $(MESH_BIN) && \
	cp target/aarch64-unknown-linux-musl/release/$(MESH_BIN) $(OUT_DIR)/mesh_linux_arm64 && \
	echo "[*] Stripping metadata..." && \
	($(STRIP_LINUX) $(OUT_DIR)/mesh_linux_arm64 2>/dev/null || strip $(OUT_DIR)/mesh_linux_arm64) && \
	echo "[+] Artifact: $(OUT_DIR)/mesh_linux_arm64"

# 5. Mesh Node (Windows AMD64 / x64)
# Target: x86_64-pc-windows-gnu
mesh_windows_amd64:
	@echo "\n[*] Building Mesh Node (Windows AMD64)..."
	@echo "[!] Warning: Requires mingw-w64 installed."
	@RUSTFLAGS="$(RUSTFLAGS_COMMON) -C link-arg=-s" \
	$(CARGO) build --release --target x86_64-pc-windows-gnu -p $(MESH_BIN) && \
	cp target/x86_64-pc-windows-gnu/release/$(MESH_BIN).exe $(OUT_DIR)/mesh_windows_amd64.exe && \
	echo "[+] Artifact: $(OUT_DIR)/mesh_windows_amd64.exe"

# 5. Optional: UPX Compression (The "Crunch")
compress:
	@echo "\n[*] Attempting UPX Compression..."
	@$(UPX) $(OUT_DIR)/mesh_macos_arm64 || echo "[!] UPX failed for macOS"
	@$(UPX) $(OUT_DIR)/mesh_linux_amd64 || echo "[!] UPX failed for Linux AMD64"
	@$(UPX) $(OUT_DIR)/mesh_linux_arm64 || echo "[!] UPX failed for Linux ARM64"
	@$(UPX) $(OUT_DIR)/mesh_windows_amd64.exe || echo "[!] UPX failed for Windows"
	@echo "[+] Compression attempts finished."

clean:
	@rm -rf $(OUT_DIR)
	@$(CARGO) clean
	@echo "[✓] Cleaned."

help:
	@echo "Phantom Mesh ULTIMATE Build"
	@echo "---------------------------"
	@echo "Targets:"
	@echo "  make all"
	@echo "  make phantom"
	@echo "  make mesh_macos_arm64"
	@echo "  make mesh_linux_amd64"
	@echo "  make mesh_linux_arm64"
	@echo "  make mesh_windows_amd64"
	@echo "  make compress"
