#!/bin/sh
# make-bench-manifest.sh SRC DST N
#
# Copy a manifest and add N bench hosts (bench-001 to bench-N, at most 500) for
# the comms bench's load run (docs/impl/14-bench.md, Task 16). The source
# manifest is never modified: only files under DST are edited.
#
# The bench addresses start just above the reference lab LAN
# (172.20.241.10 + i mod 240, third octet 241 + (i-1)/240), so the copy's lan
# segment is widened to 172.20.240.0/22 to contain them. A source without the
# reference LAN is refused rather than left invalid.

usage() {
    printf 'usage: %s SRC DST N\n' "$0" >&2
    exit 2
}

if [ $# -ne 3 ]; then
    usage
fi

src=$1
dst=$2
n=$3

case $n in
    '' | *[!0-9]*)
        printf 'bench manifest: N %s is not a number in 1..500\n' "$n" >&2
        exit 1
        ;;
esac
if [ "$n" -lt 1 ] || [ "$n" -gt 500 ]; then
    printf 'bench manifest: refusing N %s outside 1..500\n' "$n" >&2
    exit 1
fi
if [ ! -d "$src" ]; then
    printf 'bench manifest: SRC %s is not a directory\n' "$src" >&2
    exit 1
fi
if [ ! -f "$src/policy.yml" ] || [ ! -f "$src/hosts.yml" ] || [ ! -f "$src/topology.yml" ]; then
    printf 'bench manifest: SRC %s is not a manifest (needs policy.yml, hosts.yml and topology.yml)\n' "$src" >&2
    exit 1
fi
if [ -d "$dst" ] && [ -n "$(ls -A "$dst" 2>/dev/null)" ]; then
    printf 'bench manifest: refusing non-empty DST %s\n' "$dst" >&2
    exit 1
fi

mkdir -p "$dst" || exit 1
cp -R "$src"/. "$dst"/ || exit 1  # bench:ro: copies into DST only

lan=172.20.240.0/24
if ! grep -q "cidr: $lan" "$dst/topology.yml"; then
    printf 'bench manifest: SRC %s has no lan segment %s\n' "$src" "$lan" >&2
    exit 1
fi
sed "s|cidr: $lan|cidr: 172.20.240.0/22|" "$dst/topology.yml" > "$dst/topology.yml.tmp" &&
    mv "$dst/topology.yml.tmp" "$dst/topology.yml" || exit 1  # bench:ro: edits the copy in DST

i=1
while [ "$i" -le "$n" ]; do
    third=$((241 + (i - 1) / 240))
    fourth=$((10 + i % 240))
    printf '  bench-%03d: { segment: lan, ip: 172.20.%d.%d, os: { family: debian, distro: ubuntu, version: "22.04" }, roles: [] }\n' \
        "$i" "$third" "$fourth" >> "$dst/hosts.yml" || exit 1  # bench:ro: appends to the copy in DST
    i=$((i + 1))
done

printf 'bench manifest: %s (%s hosts)\n' "$dst" "$n"
