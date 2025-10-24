# Build Notes for SignalBench v1.4.3

## PACEMAKER Helper Binary Building

The S1109 PACEMAKER simulation uses an embedded helper binary located in `helpers/pacemaker/`. This binary must be compiled as a **fully static MUSL binary** to work on all Linux distributions.

### Building the Helper Binary

**Option 1: GitHub Actions (Recommended)**

The `.github/workflows/build-binary.yml` workflow automatically builds static MUSL binaries when you push tags:

```bash
git tag v1.4.3
git push && git push --tags
```

GitHub Actions will build:
- `signalbench-1.4.3-linux-musl-x86_64` (static, universal)
- `signalbench-1.4.3-linux-musl-aarch64` (static ARM64)

**Option 2: Docker (Local Development)**

```bash
docker run --rm -it -v "$(pwd)/helpers/pacemaker":/home/rust/src \
  ekidd/rust-musl-builder \
  cargo build --release

cp helpers/pacemaker/target/x86_64-unknown-linux-musl/release/pacemaker_helper \
   embedded_binaries/pacemaker_helper

# Rebuild SignalBench with new embedded binary
cargo build --release
```

**Option 3: Ubuntu/Debian with musl-tools**

```bash
sudo apt-get update && sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl

cd helpers/pacemaker
cargo build --release --target x86_64-unknown-linux-musl

cp target/x86_64-unknown-linux-musl/release/pacemaker_helper \
   ../../embedded_binaries/pacemaker_helper

cd ../..
cargo build --release
```

### Verifying Static Linking

```bash
ldd embedded_binaries/pacemaker_helper
# Should output: "not a dynamic executable" or "statically linked"

readelf -l embedded_binaries/pacemaker_helper | grep INTERP
# Should show NO output (no interpreter section)
```

### Security Features

The helper binary creation includes:
- **O_NOFOLLOW flag**: Prevents symlink attacks
- **create_new(true)**: Prevents TOCTOU vulnerabilities  
- **Explicit error handling**: Detects and reports symlink attacks
- **File handle management**: Explicit drop() calls before execution

## Version 1.4.3 Release Process

1. **Verify clippy**: `cargo clippy --all-targets --all-features -- -D warnings`
2. **Build locally**: `cargo build --release`
3. **Push to GitHub**: Let CI build portable static binaries
4. **Download artefacts**: From GitHub Actions or release page
5. **Test on target systems**: Verify static binaries work universally

## Build Environment Considerations

Some development environments may not support building fully static MUSL binaries due to:
- Limited toolchain support for `x86_64-unknown-linux-musl` targets
- Missing static GLIBC libraries
- Missing MUSL Rust standard library
- Environment-specific dynamic linker paths

In such cases, use the GitHub Actions workflow which provides a complete build environment with all necessary tools and dependencies for creating portable static binaries.
