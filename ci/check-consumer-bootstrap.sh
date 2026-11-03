#!/bin/sh
# Run the README's install recipe in a fresh directory outside the checkout:
# a new project, the documented crates.io dependency lines and program, then
# the documented build. A [patch.crates-io] table points every aauth-rust
# crate at this checkout, so the recipe is checked before the release is on
# crates.io; that table resolves only when the documented version equals the
# workspace version. Other dependencies come from the local Cargo cache.
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
checkout="$fixture/aauth-rust"

# The README's one Rust block is the library example, unchanged.
awk '
    $0 == "```rust" { blocks++; copying=1; next }
    copying && $0 == "```" { copying=0; next }
    copying { print }
    END { if (blocks != 1 || copying) exit 1 }
' "$checkout/README.md" > "$fixture/documented-main.rs"
cmp "$fixture/documented-main.rs" "$checkout/crates/aauth-rust-resource/examples/library.rs"

recipe() {
    awk -v name="$1" '
        $0 == "<!-- consumer-bootstrap-" name ":begin -->" { starts++; copying=1; next }
        $0 == "<!-- consumer-bootstrap-" name ":end -->" { ends++; copying=0; next }
        copying && $0 !~ /^```/ { print; lines++ }
        END { if (starts != 1 || ends != 1 || copying || lines < 1) exit 1 }
    ' "$checkout/README.md" > "$fixture/$2"
}
recipe setup setup.sh
recipe dependencies dependencies.toml
recipe build build.sh
sh -n "$fixture/setup.sh"
sh -n "$fixture/build.sh"

# The documented version must be the workspace version.
workspace_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$checkout/Cargo.toml" | head -1)
for documented in $(sed -n 's/^aauth-rust[a-z-]* = "\(.*\)"$/\1/p' "$fixture/dependencies.toml" | sort -u); do
    if [ "$documented" != "$workspace_version" ]; then
        echo "README documents $documented, the workspace is $workspace_version: the recipe resolves once they match" >&2
        exit 1
    fi
done

# Cache-backed qualification with the checkout's toolchain.
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2
RUSTUP_TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$checkout/rust-toolchain.toml")
export RUSTUP_TOOLCHAIN
cd "$fixture"
sh -e "$fixture/setup.sh"
consumer="$fixture/aauth-service"
test -f "$consumer/Cargo.toml"
# The documented setup refuses an existing project and leaves it unchanged.
cp "$consumer/Cargo.toml" "$fixture/Cargo.toml.before-refusal"
if sh -e "$fixture/setup.sh" > "$fixture/existing-directory-refusal.log" 2>&1; then
    echo 'setup unexpectedly accepted an existing project' >&2
    exit 1
fi
cmp "$fixture/Cargo.toml.before-refusal" "$consumer/Cargo.toml"

# What the reader does by hand: the dependency lines, then the program.
grep -qx '\[dependencies\]' "$consumer/Cargo.toml"
cat "$fixture/dependencies.toml" >> "$consumer/Cargo.toml"
cp "$fixture/documented-main.rs" "$consumer/src/main.rs"
{
    printf '\n[patch.crates-io]\n'
    for crate in "$checkout"/crates/*; do
        printf '%s = { path = "%s" }\n' "$(basename "$crate")" "$crate"
    done
} >> "$consumer/Cargo.toml"

(cd "$consumer" && sh -e "$fixture/build.sh") > "$fixture/run.log"
cat "$fixture/run.log"
grep -qx 'verified aauth:Agent@ap.example' "$fixture/run.log"
cp "$consumer/Cargo.lock" "$fixture/Cargo.lock.after-run"
(cd "$consumer" && cargo build --locked)
cmp "$fixture/Cargo.lock.after-run" "$consumer/Cargo.lock"

printf '%s\n' 'consumer bootstrap: new project, documented dependencies and program, existing-project refusal, run and locked rebuild'
sha256sum "$consumer/Cargo.toml" "$consumer/src/main.rs" "$consumer/Cargo.lock"
