# snoopworld

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build ALL on mac

```bash
cargo xtask build-ebpf --release && RUSTFLAGS="-Clinker=aarch64-linux-musl-ld" cargo build --target=aarch64-unknown-linux-musl --release
```

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
