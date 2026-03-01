#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

MISSING_PKGS=()

check_cmd() {
    local cmd="$1"; shift
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd found"
    else
        warn "$cmd not found"
        MISSING_PKGS+=("$@")
    fi
}

check_pkg() {
    if dpkg -s "$1" 2>/dev/null | grep -q "Status: install ok installed"; then
        ok "$1 installed"
    else
        warn "$1 not installed"
        MISSING_PKGS+=("$1")
    fi
}

verify_tarball() {
    local path="$1"
    [ -f "$path" ] && gzip -t "$path" >/dev/null 2>&1
}

echo ""
echo "=== Havoc Dependency Check ==="
echo ""

check_cmd go golang-go
check_cmd nasm nasm
check_cmd cmake cmake
check_cmd g++ g++
check_cmd git git
check_cmd wget wget
check_cmd python3 python3

check_pkg mingw-w64
check_pkg qtbase5-dev
check_pkg libqt5websockets5-dev
check_pkg python3-dev
check_pkg libpython3-dev

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    UNIQUE_PKGS=($(echo "${MISSING_PKGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    echo ""
    warn "Missing packages: ${UNIQUE_PKGS[*]}"
    warn "Installing..."
    sudo apt update -qq
    sudo apt install -y "${UNIQUE_PKGS[@]}"
    ok "Packages installed"
else
    echo ""
    ok "All system packages present"
fi

echo ""
echo "=== Musl Cross-Compilers ==="
echo ""

mkdir -p data

if [ ! -d "data/x86_64-w64-mingw32-cross" ]; then
    if ! verify_tarball /tmp/mingw-musl-64.tgz; then
        rm -f /tmp/mingw-musl-64.tgz
        echo "Downloading x64 musl cross-compiler..."
        wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q --show-progress -O /tmp/mingw-musl-64.tgz
    fi
    tar zxf /tmp/mingw-musl-64.tgz -C data
    ok "x64 cross-compiler installed"
else
    ok "x64 cross-compiler already present"
fi

if [ ! -d "data/i686-w64-mingw32-cross" ]; then
    if ! verify_tarball /tmp/mingw-musl-32.tgz; then
        rm -f /tmp/mingw-musl-32.tgz
        echo "Downloading x86 musl cross-compiler..."
        wget https://musl.cc/i686-w64-mingw32-cross.tgz -q --show-progress -O /tmp/mingw-musl-32.tgz
    fi
    tar zxf /tmp/mingw-musl-32.tgz -C data
    ok "x86 cross-compiler installed"
else
    ok "x86 cross-compiler already present"
fi

echo ""
ok "Ready to build"
echo ""
