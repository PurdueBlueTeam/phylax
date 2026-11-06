#!/bin/sh
# c1-capture.sh start|stop|status -- raw packet capture for the Invitational (C1).
# Observe only: writes under $INV_ROOT only, and start/stop touch only the two
# tcpdump processes it started. Run it as root (tcpdump needs raw sockets).
#
#   SCORED_PORTS  scored ports (replace from the team packet)
#   IFACE         capture interface (default any)
#   INV_MIN_FREE_MB  refuse to start below this much free space (default 6000)

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$here/lib.sh"

# Team packet: replace this list with the scored ports from the appendix.
SCORED_PORTS=${SCORED_PORTS:-"21 22 25 53 80 110 143 389 443 445 465 587 993 995 1433 3306 5985 8089"}
IFACE=${IFACE:-any}
INV_MIN_FREE_MB=${INV_MIN_FREE_MB:-6000}
INV_ROOT=${INV_ROOT:-/var/tmp/phylax-inv}
INV_HOST=${INV_HOST:-$(hostname -s 2>/dev/null || hostname)}
export INV_ROOT INV_HOST

HOST=$INV_HOST
PCAP_DIR=$INV_ROOT/pcap
PIDS=$PCAP_DIR/c1.pids

_filter_scored() {
    sep=
    for port in $SCORED_PORTS; do
        printf '%sport %s' "$sep" "$port"
        sep=' or '
    done
}

# _live_pids: print the pids in c1.pids that are still running.
_live_pids() {
    [ -f "$PIDS" ] || return 0
    while read -r pid; do
        [ -n "$pid" ] || continue
        if kill -0 "$pid" 2>/dev/null; then # inv:ro: checks only our own tcpdump pids
            printf '%s\n' "$pid"
        fi
    done < "$PIDS"
}

_free_mb() {
    df -Pm "$PCAP_DIR" 2>/dev/null | awk 'NR == 2 { print $4 }'
}

_start() {
    mkdir -p "$PCAP_DIR" || {
        printf 'c1: cannot create %s\n' "$PCAP_DIR" >&2
        return 1
    }

    live=$(_live_pids | head -n 1)
    if [ -n "$live" ]; then
        printf 'c1: already running (pid %s); stop it first\n' "$live" >&2
        return 1
    fi

    free_mb=$(_free_mb)
    case $free_mb in
        ''|*[!0-9]*) free_mb=0 ;;
    esac
    if [ "$free_mb" -lt "$INV_MIN_FREE_MB" ]; then
        printf 'c1: refusing to start: %s MB free under %s, need %s MB\n' \
            "$free_mb" "$INV_ROOT" "$INV_MIN_FREE_MB" >&2
        return 1
    fi

    scored_filter=$(_filter_scored)
    other_filter="not ($scored_filter)"
    scored_file=$PCAP_DIR/$HOST-scored.pcap
    other_file=$PCAP_DIR/$HOST-other.pcap

    if [ "${INV_DRY:-}" = 1 ]; then
        printf "tcpdump -i %s -nn -s 1500 -C 100 -W 20 -w %s '%s'\n" \
            "$IFACE" "$scored_file" "$scored_filter"
        printf "tcpdump -i %s -nn -s 256 -C 100 -W 20 -w %s '%s'\n" \
            "$IFACE" "$other_file" "$other_filter"
        return 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        printf 'c1: refusing to start: tcpdump needs root (try sudo)\n' >&2
        return 1
    fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        printf 'c1: refusing to start: tcpdump not found\n' >&2
        return 1
    fi

    inv_init c1 >/dev/null || printf 'c1: could not write run metadata\n' >&2

    tcpdump -i "$IFACE" -nn -s 1500 -C 100 -W 20 -w "$scored_file" "$scored_filter" \
        2>"$PCAP_DIR/tcpdump-scored.log" &
    scored_pid=$!
    tcpdump -i "$IFACE" -nn -s 256 -C 100 -W 20 -w "$other_file" "$other_filter" \
        2>"$PCAP_DIR/tcpdump-other.log" &
    other_pid=$!

    printf '%s\n%s\n' "$scored_pid" "$other_pid" > "$PIDS"
    printf 'c1: started scored pid %s and other pid %s in %s\n' \
        "$scored_pid" "$other_pid" "$PCAP_DIR"
}

_stop() {
    if [ ! -f "$PIDS" ]; then
        printf 'c1: no pid file at %s\n' "$PIDS" >&2
        return 1
    fi

    while read -r pid; do
        [ -n "$pid" ] || continue
        if kill -0 "$pid" 2>/dev/null; then # inv:ro: stops only our own tcpdump pids
            kill -INT "$pid" 2>/dev/null # inv:ro: stops only our own tcpdump pids
        fi
    done < "$PIDS"

    waited=0
    while [ "$waited" -lt 10 ]; do
        [ -z "$(_live_pids)" ] && break
        sleep 1
        waited=$((waited + 1))
    done

    : > "$PCAP_DIR/drops.txt"
    for log in "$PCAP_DIR/tcpdump-scored.log" "$PCAP_DIR/tcpdump-other.log"; do
        [ -f "$log" ] || continue
        grep 'packets dropped by kernel' "$log" >> "$PCAP_DIR/drops.txt"
    done

    printf 'c1: stopped (%s s); drops in %s\n' "$waited" "$PCAP_DIR/drops.txt"
}

_status() {
    printf 'c1: %s\n' "$(inv_utc)"
    if [ -f "$PIDS" ]; then
        while read -r pid; do
            [ -n "$pid" ] || continue
            if kill -0 "$pid" 2>/dev/null; then # inv:ro: checks only our own tcpdump pids
                printf 'pid %s: running\n' "$pid"
            else
                printf 'pid %s: not running\n' "$pid"
            fi
        done < "$PIDS"
    else
        printf 'pid file: absent (%s)\n' "$PIDS"
    fi

    if [ -d "$PCAP_DIR" ]; then
        ls -l "$PCAP_DIR"
    else
        printf 'capture directory: absent (%s)\n' "$PCAP_DIR"
    fi

    if [ -f "$PCAP_DIR/drops.txt" ]; then
        printf -- '-- drops.txt --\n'
        cat "$PCAP_DIR/drops.txt"
    fi
}

case ${1:-} in
    start) _start ;;
    stop) _stop ;;
    status) _status ;;
    *)
        printf 'usage: sh c1-capture.sh start|stop|status\n' >&2
        exit 2
        ;;
esac
