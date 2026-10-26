#!/bin/sh
# Compile the exact README recipe in a fresh sibling layout; never run the app.
set -eu
source_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
fixture=${1:?usage: sh ci/check-consumer-bootstrap.sh ABSENT_ABSOLUTE_FIXTURE}
case "$fixture" in
    /*) ;;
    *) echo 'fixture must be an absolute unused path' >&2; exit 1 ;;
esac
mkdir "$fixture"
mkdir "$fixture/aauth-rust"

# Copy tracked checkout bytes, including edited documentation during local checks.
# Do not copy .git, private untracked configuration, or existing build output.
git -C "$source_root" ls-files -z > "$fixture/tracked-files"
tar -C "$source_root" --null -T "$fixture/tracked-files" -cf "$fixture/checkout.tar"
tar -C "$fixture/aauth-rust" -xf "$fixture/checkout.tar"
awk '
    $0 == "```rust" { blocks++; copying=1; next }
    copying && $0 == "```" { copying=0; next }
    copying { print }
    END { if (blocks != 1 || copying) exit 1 }
' "$fixture/aauth-rust/README.md" > "$fixture/documented-main.rs"
cmp "$fixture/documented-main.rs" "$fixture/aauth-rust/crates/aauth-rust-resource/examples/library.rs"

recipe() {
    awk -v name="$1" '
        $0 == "<!-- consumer-bootstrap-" name ":begin -->" { starts++; copying=1; next }
        $0 == "<!-- consumer-bootstrap-" name ":end -->" { ends++; copying=0; next }
        copying && $0 !~ /^```/ { print; lines++ }
        END { if (starts != 1 || ends != 1 || copying || lines < 1) exit 1 }
    ' "$fixture/aauth-rust/README.md" > "$fixture/$1.sh"
    sh -n "$fixture/$1.sh"
}
recipe setup
recipe build
test ! -e "$fixture/aauth-service"

# Cache-backed qualification only. Ordinary users may need registry downloads.
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2
cd "$fixture/aauth-rust"
sh "$fixture/setup.sh"
consumer="$fixture/aauth-service"
cmp rust-toolchain.toml "$consumer/rust-toolchain.toml"
cmp crates/aauth-rust-resource/examples/library.rs "$consumer/src/main.rs"
cp "$consumer/Cargo.lock" "$fixture/Cargo.lock.before-build"
# The documented setup must refuse an existing application before overwriting it.
cp "$consumer/Cargo.toml" "$fixture/Cargo.toml.documented"
printf '\n# Existing consumer-owned configuration must survive setup refusal.\n' >> "$consumer/Cargo.toml"
cp "$consumer/Cargo.toml" "$fixture/Cargo.toml.before-refusal"
if sh "$fixture/setup.sh" > "$fixture/existing-directory-refusal.log" 2>&1; then
    echo 'setup unexpectedly accepted an existing application' >&2
    exit 1
fi
cmp "$fixture/Cargo.toml.before-refusal" "$consumer/Cargo.toml"
cmp "$fixture/Cargo.lock.before-build" "$consumer/Cargo.lock"
cmp rust-toolchain.toml "$consumer/rust-toolchain.toml"
cmp "$fixture/documented-main.rs" "$consumer/src/main.rs"
cp "$fixture/Cargo.toml.documented" "$consumer/Cargo.toml"
sh "$fixture/build.sh"
cmp "$fixture/Cargo.lock.before-build" "$consumer/Cargo.lock"

printf '%s\n' 'consumer bootstrap: own toolchain, initial lockfile, existing-directory refusal and locked build; app not executed'
sha256sum "$consumer/Cargo.toml" "$consumer/rust-toolchain.toml" \
    "$consumer/src/main.rs" "$consumer/Cargo.lock"
