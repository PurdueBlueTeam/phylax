#!/bin/sh
# scribe.sh -- C7 outside-scribe sheet for the Invitational. Runs on the
# scribe's own machine (any POSIX shell or Git Bash), never inside the
# environment, and writes only in the current directory: the files are uploaded
# to Nextcloud by hand afterwards.
#
#   sh scribe.sh init
#       create scribe.csv with its header; a second init leaves the sheet alone
#   sh scribe.sh row SERVICE STATUS SCORE [NOTE]
#       append one scoreboard row (UTC, round note, svc, status, score)
#   sh scribe.sh pcr SECONDS
#       record the S13 PCR submit time (UTC and elapsed seconds) in pcr.txt
#   sh scribe.sh credlists FILE
#       copy the scribe's saved GET /api/credlists output to
#       credlists-<utc>.json, for S14
#
# Column order is fixed by the plan; HEADER below spells it out. The marker on
# that line is for its data labels, which are not command calls.

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$HERE/lib.sh"

CSV=scribe.csv
HEADER='utc,round_note,service,status,score,source' # inv:ro: CSV column name

usage() {
    printf 'usage: sh scribe.sh init | row SERVICE STATUS SCORE [NOTE] | pcr SECONDS | credlists FILE\n' >&2
    exit 2
}

# _header: the sheet has its header exactly once.
_header() {
    [ -s "$CSV" ] || printf '%s\n' "$HEADER" > "$CSV"
}

cmd=${1:-}
if [ $# -gt 0 ]; then
    shift
fi

case $cmd in
    init)
        if [ -s "$CSV" ]; then
            printf '%s: already initialised, keeping the existing sheet\n' "$CSV" >&2
        else
            _header
            printf '%s\n' "$CSV"
        fi
        ;;
    row)
        if [ $# -lt 3 ]; then
            usage
        fi
        _header
        svc=$1
        status=$2
        score=$3
        shift 3
        # shortcut: note and svc go into the CSV unquoted, so neither may
        # contain a comma; quote fields when a note needs one.
        printf '%s,%s,%s,%s,%s,board\n' "$(inv_utc)" "$*" "$svc" "$status" "$score" >> "$CSV" || exit 1
        ;;
    pcr)
        if [ $# -lt 1 ]; then
            usage
        fi
        case $1 in
            ''|*[!0-9]*)
                printf 'scribe: SECONDS must be whole seconds, not [%s]\n' "$1" >&2
                exit 2
                ;;
        esac
        printf '%s\t%s\n' "$(inv_utc)" "$1" >> pcr.txt || exit 1
        printf 'pcr.txt: %s %s\n' "$(inv_utc)" "$1"
        ;;
    credlists)
        if [ $# -lt 1 ]; then
            usage
        fi
        file=$1
        if [ ! -s "$file" ]; then
            printf 'scribe: cannot read %s\n' "$file" >&2
            exit 1
        fi
        base="credlists-$(inv_stamp)"
        dest=$base.json
        n=1
        while [ -e "$dest" ]; do
            n=$((n + 1))
            dest="$base-$n.json"
        done
        cat "$file" > "$dest" || exit 1
        printf '%s\n' "$dest"
        ;;
    ''|-h|--help)
        usage
        ;;
    *)
        printf 'scribe: unknown command: %s\n' "$cmd" >&2
        usage
        ;;
esac
