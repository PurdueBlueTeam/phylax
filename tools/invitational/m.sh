#!/bin/sh
# m.sh TEXT... -- append one line to the Invitational ops timeline (C6).
#
# Typed as `sh m.sh drop flag` or `sh m.sh console open rocky`. With no
# arguments it prints the last 5 lines. The file is
# ${INV_TIMELINE:-$INV_ROOT/timeline.txt}, default /var/tmp/phylax-inv on Linux.
# Observe only: the one write is the timeline under INV_ROOT.

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$HERE/lib.sh"

INV_ROOT=${INV_ROOT:-/var/tmp/phylax-inv}
INV_TIMELINE=${INV_TIMELINE:-$INV_ROOT/timeline.txt}
INV_HOST=${INV_HOST:-$(hostname -s 2>/dev/null || hostname)}

if [ $# -eq 0 ]; then
    if [ -f "$INV_TIMELINE" ]; then
        tail -n 5 "$INV_TIMELINE"
    fi
    exit 0
fi

mkdir -p "$(dirname "$INV_TIMELINE")" || exit 1
line=$(printf '%s\t%s\t%s' "$(inv_utc)" "$INV_HOST" "$*")
printf '%s\n' "$line" >> "$INV_TIMELINE" || exit 1
printf '%s\n' "$line"
