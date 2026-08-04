#!/usr/bin/env sh
set -eu

target="x86_64-unknown-linux-musl"
binary="target/$target/release/share2me"

if ! rustup target list --installed | grep -qx "$target"; then
    echo "error: Rust target '$target' is not installed" >&2
    echo "install it with: rustup target add $target" >&2
    exit 1
fi

# Native crypto dependencies need a C compiler pointed at the same musl ABI.
if command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
    CC_x86_64_unknown_linux_musl="x86_64-linux-musl-gcc"
elif command -v musl-gcc >/dev/null 2>&1; then
    CC_x86_64_unknown_linux_musl="musl-gcc"
elif command -v clang >/dev/null 2>&1 \
    && test -d /usr/x86_64-linux-musl/include \
    && test -d /usr/x86_64-linux-musl/lib64; then
    CC_x86_64_unknown_linux_musl="clang"
    CFLAGS_x86_64_unknown_linux_musl="--target=x86_64-linux-musl --sysroot=/usr/x86_64-linux-musl ${CFLAGS_x86_64_unknown_linux_musl:-}"
    export CFLAGS_x86_64_unknown_linux_musl
else
    echo "error: no usable x86-64 musl C toolchain was found" >&2
    echo "Fedora: sudo dnf install clang musl-devel musl-libc-static" >&2
    echo "Debian/Ubuntu: sudo apt-get install musl-tools" >&2
    exit 1
fi
export CC_x86_64_unknown_linux_musl

cargo build --release --locked --target "$target" "$@"

if command -v readelf >/dev/null 2>&1; then
    if readelf -l "$binary" | grep -q INTERP; then
        echo "error: $binary contains a dynamic ELF interpreter" >&2
        exit 1
    fi
    if readelf -d "$binary" | grep -q NEEDED; then
        echo "error: $binary contains dynamic library dependencies" >&2
        exit 1
    fi
fi

echo "Static binary: $binary"
