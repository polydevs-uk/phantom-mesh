#!/bin/bash
# Phantom-Mesh Botnet Toolchain Setup
# Downloads RootSec cross-compilers for multi-arch build.

mkdir -p toolchains
cd toolchains

echo "[*] Downloading Cross-Compilers..."

# List of compilers
declare -a urls=(
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-i586.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-i686.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-m68k.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-mips.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-mipsel.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-powerpc.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-sh4.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-sparc.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv4l.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv5l.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv6l.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv7l.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-powerpc-440fp.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-x86_64.tar.bz2"
    "https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-i486.tar.gz"
)

for url in "${urls[@]}"; do
    file=$(basename "$url")
    if [ ! -f "$file" ]; then
        echo "Downloading $file..."
        wget -q --show-progress "$url"
    else
        echo "$file already exists. Skipping."
    fi
    
    # Extract
    echo "Extracting $file..."
    if [[ "$file" == *.tar.bz2 ]]; then
        tar -xjf "$file"
    elif [[ "$file" == *.tar.gz ]]; then
        tar -xzf "$file"
    fi
done

echo "[+] Toolchains setup complete in $(pwd)"
