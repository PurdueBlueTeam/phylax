#!/bin/sh
# Shared helpers for the Invitational collectors. Observe only: every helper
# writes under $INV_ROOT, never to the host's configuration or running state.

inv_utc() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

inv_stamp() {
    date -u '+%Y%m%dT%H%M%SZ'
}

# One line describing the host's clock offset, from the first query that works.
_inv_ntp_line() {
    if command -v chronyc >/dev/null 2>&1; then
        line=$(chronyc tracking 2>/dev/null | grep -i 'System time' | head -n 1)
        if [ -n "$line" ]; then
            printf 'chronyc: %s\n' "$line"
            return 0
        fi
    fi
    if command -v timedatectl >/dev/null 2>&1; then
        line=$(timedatectl show-timesync 2>/dev/null | head -n 1)
        if [ -n "$line" ]; then
            printf 'timedatectl: %s\n' "$line"
            return 0
        fi
    fi
    if command -v ntpq >/dev/null 2>&1; then
        line=$(ntpq -pn 2>/dev/null | sed -n '3p')
        if [ -z "$line" ]; then
            line=$(ntpq -pn 2>/dev/null | sed -n '1p')
        fi
        if [ -n "$line" ]; then
            printf 'ntpq: %s\n' "$line"
            return 0
        fi
    fi
    printf 'ntp: unavailable\n'
}

# inv_init CID: create a fresh output directory for one collector run.
inv_init() {
    INV_CID=${1:-}
    INV_ROOT=${INV_ROOT:-/var/tmp/phylax-inv}
    INV_HOST=${INV_HOST:-$(hostname -s 2>/dev/null || hostname)}
    INV_STAMP=$(inv_stamp)
    export INV_ROOT INV_HOST INV_CID INV_STAMP

    mkdir -p "$INV_ROOT/$INV_HOST" || return 1

    base="$INV_ROOT/$INV_HOST/$INV_CID-$INV_STAMP"
    INV_OUT=$base
    n=1
    while [ -e "$INV_OUT" ]; do
        n=$((n + 1))
        INV_OUT="$base-$n"
    done
    mkdir "$INV_OUT" || return 1
    export INV_OUT

    {
        printf 'utc: %s\n' "$(inv_utc)"
        printf 'host: %s\n' "$INV_HOST"
        printf 'uname: %s\n' "$(uname -a 2>/dev/null)"
        _inv_ntp_line
    } > "$INV_OUT/_meta.txt"
}

# inv_run NAME CMD [ARG...]: capture one command's output and record its exit
# status and duration. Never aborts the collector.
inv_run() {
    name=$1
    shift
    start=$(date +%s)
    if [ $# -gt 0 ]; then
        "$@" > "$INV_OUT/$name.txt" 2>&1
    else
        : > "$INV_OUT/$name.txt"
    fi
    code=$?
    end=$(date +%s)
    secs=$((end - start))
    printf '%s\t%s\t%s\n' "$name" "$code" "$secs" >> "$INV_OUT/_index.tsv"
    return 0
}

# inv_pack: archive this run's directory and print "PATH BYTES SHA256".
inv_pack() {
    base="$INV_ROOT/$INV_HOST-$INV_CID-$INV_STAMP"
    archive="$base.tar.gz"
    n=1
    while [ -e "$archive" ]; do
        n=$((n + 1))
        archive="$base-$n.tar.gz"
    done

    parent=$(dirname "$INV_OUT")
    leaf=$(basename "$INV_OUT")
    tar -czf "$archive" -C "$parent" "$leaf" || return 1

    bytes=$(wc -c < "$archive" | tr -d '[:space:]')
    if command -v sha256sum >/dev/null 2>&1; then
        sum=$(sha256sum "$archive" | cut -d' ' -f1)
    else
        sum=$(shasum -a 256 "$archive" | cut -d' ' -f1)
    fi
    printf '%s %s %s\n' "$archive" "$bytes" "$sum"
}
