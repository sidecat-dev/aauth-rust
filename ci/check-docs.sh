#!/bin/sh
# Check README.md and docs/: samples quoted from source files still match them,
# relative links and heading anchors resolve, and every page with a Rust sample
# is compiled as doctests by a crate. Builds nothing.
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pages="README.md $(find docs -name '*.md' | sort)"

# A quoted sample is a fenced block right after `<!-- sample: PATH -->`; its
# text must appear unchanged in PATH. Other `rust ...` blocks need a marker.
for page in $pages; do
    awk -v page="$page" '
        function slurp(path,   line, text) {
            text = ""
            while ((getline line < path) > 0) text = text line "\n"
            close(path)
            return text
        }
        inblock && /^```$/ {
            inblock = 0
            if (source == "") next
            text = slurp(source)
            if (text == "") { printf "%s: sample source %s is missing\n", page, source; bad = 1 }
            else if (index(text, block) == 0) { printf "%s: sample no longer matches %s\n", page, source; bad = 1 }
            source = ""
            next
        }
        inblock { block = block $0 "\n"; next }
        /^<!-- sample: [^ ]+ -->$/ { source = $3; want = 1; next }
        /^```/ {
            if (want != 1) {
                source = ""
                if ($0 ~ /^```rust./) { printf "%s: %s block has no sample marker\n", page, $0; bad = 1 }
            }
            want = 0; inblock = 1; block = ""
            next
        }
        want == 1 { printf "%s: sample marker for %s has no code block after it\n", page, source; bad = 1; want = 0; source = "" }
        END { exit bad }
    ' "$page" || echo "$page" >> "$work/failed"
done

# GitLab heading anchors: lowercase, drop punctuation, spaces to hyphens.
anchors() {
    awk '/^```/ { fence = !fence; next } !fence && /^#+ / { sub(/^#+ +/, ""); print }' "$1" |
        tr 'A-Z' 'a-z' | sed 's/[^a-z0-9 _-]//g; s/ /-/g; s/--*/-/g'
}

for page in $pages; do
    dir=$(dirname "$page")
    awk '/^```/ { fence = !fence; next } !fence { print }' "$page" |
        grep -o '](\([^)]*\))' | sed 's/^](//; s/)$//' | while read -r target; do
            case "$target" in
                http://* | https://* | mailto:*) continue ;;
            esac
            file=${target%%#*}
            anchor=
            case "$target" in *'#'*) anchor=${target#*#} ;; esac
            if [ -z "$file" ]; then path=$page; else path=$dir/$file; fi
            if [ ! -e "$path" ]; then
                echo "$page: broken link $target"
                echo "$page" >> "$work/failed"
            elif [ -n "$anchor" ] && [ "${path%.md}" != "$path" ] &&
                ! anchors "$path" | grep -qx -- "$anchor"; then
                echo "$page: no heading for $target"
                echo "$page" >> "$work/failed"
            fi
        done
done

# The README's one Rust block is checked by ci/check-consumer-bootstrap.sh.
for page in $pages; do
    [ "$page" = README.md ] && continue
    grep -qx '```rust' "$page" || continue
    if ! grep -qF "include_str!(\"../../../$page\")" crates/*/src/lib.rs; then
        echo "$page: has Rust samples, but no crate compiles them"
        echo "$page" >> "$work/failed"
    fi
done

if [ -s "$work/failed" ]; then
    echo "docs check failed: $(sort -u "$work/failed" | tr '\n' ' ')" >&2
    exit 1
fi
echo "docs check: samples, links and doctest coverage pass for $(echo $pages | wc -w) pages"
