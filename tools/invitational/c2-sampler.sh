#!/bin/sh
# c2-sampler.sh start|stop -- one resource row per INTERVAL seconds (E14, O3).
#
# Appends to $INV_ROOT/sampler.csv:
#   utc,load1,mem_avail_kb,root_used_pct,cpu_busy_pct
# Observe only: it writes the CSV and its own pid file, nothing else.
#
#   INTERVAL         seconds between rows (default 60)
#   INV_SAMPLE_ONCE  write one row and exit (used by the test)
#
# Usage: sh c2-sampler.sh start|stop

INV_ROOT=${INV_ROOT:-/var/tmp/phylax-inv}
INTERVAL=${INTERVAL:-60}
CSV=$INV_ROOT/sampler.csv
PIDFILE=$INV_ROOT/sampler.pid
HEADER='utc,load1,mem_avail_kb,root_used_pct,cpu_busy_pct'

# Idle jiffies and total jiffies from one /proc/stat read.
_cpu_jiffies() {
    awk '/^cpu / {
        total = 0
        for (i = 2; i <= NF; i++) total += $i
        printf "%d %d\n", $5 + $6, total
        exit
    }' /proc/stat
}

# One CSV row on stdout.
_sample_row() {
    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    load1=$(cut -d' ' -f1 /proc/loadavg)
    mem=$(awk '/^MemAvailable:/ { print $2; found = 1; exit }
        END { if (!found) exit 1 }' /proc/meminfo)
    if [ -z "$mem" ]; then
        mem=$(awk '/^MemFree:/ { print $2; exit }' /proc/meminfo)
    fi
    root=$(df -P / 2>/dev/null | awk 'NR == 2 {
        if ($3 + $4 > 0) printf "%.0f", $3 * 100 / ($3 + $4)
        else print 0
    }')
    set -- $(_cpu_jiffies)
    idle1=$1
    total1=$2
    sleep 1
    set -- $(_cpu_jiffies)
    didle=$(( $1 - idle1 ))
    dtotal=$(( $2 - total1 ))
    if [ "$dtotal" -gt 0 ]; then
        cpu=$(( (dtotal - didle) * 100 / dtotal ))
    else
        cpu=0
    fi
    printf '%s,%s,%s,%s,%s\n' "$now" "$load1" "$mem" "$root" "$cpu"
}

_alive() {
    [ -n "$1" ] && kill -0 "$1" 2>/dev/null # inv:ro: checks our own sampler pid
}

mkdir -p "$INV_ROOT" || exit 1

case ${1:-} in
start)
    if [ ! -f "$CSV" ]; then
        printf '%s\n' "$HEADER" > "$CSV" || exit 1
    fi
    if [ "${INV_SAMPLE_ONCE:-0}" = 1 ]; then
        _sample_row >> "$CSV"
        exit 0
    fi
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        if _alive "$pid"; then
            printf 'c2-sampler: already running (pid %s)\n' "$pid" >&2
            exit 1
        fi
    fi
    (
        while :; do
            _sample_row >> "$CSV"
            sleep "$INTERVAL"
        done
    ) &
    pid=$!
    printf '%s\n' "$pid" > "$PIDFILE"
    printf 'c2-sampler: started (pid %s, csv %s, interval %ss)\n' "$pid" "$CSV" "$INTERVAL"
    ;;
stop)
    if [ ! -f "$PIDFILE" ]; then
        printf 'c2-sampler: not running (no %s)\n' "$PIDFILE" >&2
        exit 1
    fi
    pid=$(cat "$PIDFILE" 2>/dev/null)
    if _alive "$pid"; then
        kill "$pid" 2>/dev/null # inv:ro: stops only our own sampler pid
        i=0
        while [ "$i" -lt 10 ] && _alive "$pid"; do
            i=$((i + 1))
            sleep 1
        done
    fi
    rm -f "$PIDFILE" # inv:ro: our own pid file under INV_ROOT
    printf 'c2-sampler: stopped (csv %s)\n' "$CSV"
    ;;
*)
    printf 'usage: sh c2-sampler.sh start|stop\n' >&2
    exit 2
    ;;
esac
