#!/bin/sh
# make-observe-manifest.sh SRC DST [--no-decoys]
#
# Copy a manifest into an observe-mode one: no outbound canary probes and no
# capture role (every host, the kit's c1 records the pcaps), and optionally no
# decoys. The source manifest is never modified: only files under DST are
# edited.

usage() {
    printf 'usage: %s SRC DST [--no-decoys]\n' "$0" >&2
    exit 2
}

if [ $# -lt 2 ]; then
    usage
fi

src=$1
dst=$2
shift 2

no_decoys=0
for arg in "$@"; do
    case $arg in
        --no-decoys) no_decoys=1 ;;
        *) usage ;;
    esac
done

if [ ! -d "$src" ]; then
    printf 'observe manifest: SRC %s is not a directory\n' "$src" >&2
    exit 1
fi
if [ ! -f "$src/policy.yml" ] || [ ! -f "$src/hosts.yml" ]; then
    printf 'observe manifest: SRC %s is not a manifest (needs policy.yml and hosts.yml)\n' "$src" >&2
    exit 1
fi
if [ -d "$dst" ] && [ -n "$(ls -A "$dst" 2>/dev/null)" ]; then
    printf 'observe manifest: refusing non-empty DST %s\n' "$dst" >&2
    exit 1
fi

mkdir -p "$dst" || exit 1
cp -R "$src"/. "$dst"/ || exit 1  # inv:ro: copies into DST only

# Rewrite one file of the copy in place; sed reads, the temp file is the edit.
_edit() {
    file=$1
    shift
    sed "$@" "$file" > "$file.tmp" && mv "$file.tmp" "$file" || exit 1  # inv:ro: edits the copy in DST
}

# Observe mode sends no canary probes from any host.
_edit "$dst/policy.yml" -e 's/canary_ports: \[[^]]*\]/canary_ports: []/'

# Observe mode has no capture role: the kit's c1-capture records the pcaps, and
# the agent's capture module would hold 512 MiB in the Go heap, over the 256M
# MemoryMax default. Drop the module block if the source manifest has one.
rm -f "$dst/modules/capture.yml" "$dst/capture.yml" || exit 1  # inv:ro: deletes only the copy in DST
_edit "$dst/hosts.yml" \
    -e 's/roles: \[capture\]/roles: []/' \
    -e 's/roles: \[capture, /roles: [/' \
    -e 's/, capture\]/]/' \
    -e 's/, capture, /, /'

if [ "$no_decoys" -eq 1 ]; then
    rm -f "$dst/decoys.yml" || exit 1  # inv:ro: deletes only the copy in DST
    _edit "$dst/hosts.yml" \
        -e 's/, decoys\]/]/' \
        -e 's/\[decoys, /[/' \
        -e 's/roles: \[decoys\]/roles: []/'
fi

printf 'observe manifest: %s\n' "$dst"
