#!/bin/sh
# e.sh CTL HOST [agent] -- console enrollment for the Invitational, fetched by URL.
#
# Typed as (CTL is a copy of this file named "e" on the controller):
#   curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 ubuntu-email agent
#
#   CTL   controller host:port serving the kit over HTTP
#   HOST  manifest host name; its bundle is fetched as CTL/HOST.json
#   agent also fetch phylax and HOST.json and run `phylax agent install`
#
# Without "agent" only the collector kit is fetched and extracted. Every step
# prints a UTC line, so the console transcript doubles as a timeline.
#
# Self-contained by design: it is piped into sh, so it cannot source lib.sh
# until the kit is on disk; utc() below is the local copy of inv_utc.
#
# shortcut: the typed line is 70 visible characters (71 with the Enter key), at
# the 70-character goal with no headroom; shorten the path or the host name when
# Task 15 shows the consoles reject a line that long.

utc() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

say() {
    printf '%s %s\n' "$(utc)" "$*"
}

if [ $# -lt 2 ]; then
    printf 'usage: sh e.sh CTL HOST [agent]\n' >&2
    exit 2
fi

CTL=$1
HOST=$2
MODE=${3:-}

case $CTL in
    http://*|https://*) BASE=$CTL ;;
    *) BASE=http://$CTL ;;
esac

INV_KIT=${INV_KIT:-/var/tmp/phylax-kit}
INV_BIN=${INV_BIN:-/var/tmp/phylax-bin}

# fetch URL DEST: download one file; non-zero on failure or an empty result.
fetch() {
    url=$1
    dest=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -o "$dest" "$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url" || return 1
    else
        say "error: neither curl nor wget is available"
        return 1
    fi
    [ -s "$dest" ]
}

mkdir -p "$INV_KIT" || exit 1
say "kit: downloading $BASE/kit.tgz"
if ! fetch "$BASE/kit.tgz" "$INV_KIT/kit.tgz"; then
    say "error: could not download $BASE/kit.tgz"
    exit 1
fi
say "kit: extracting into $INV_KIT"
if ! tar -xzf "$INV_KIT/kit.tgz" -C "$INV_KIT"; then
    say "error: could not extract $INV_KIT/kit.tgz"
    exit 1
fi

if [ "$MODE" = agent ]; then
    mkdir -p "$INV_BIN" || exit 1
    say "agent: downloading $BASE/phylax"
    if ! fetch "$BASE/phylax" "$INV_BIN/phylax"; then
        say "error: could not download $BASE/phylax"
        exit 1
    fi
    say "agent: downloading $BASE/$HOST.json"
    if ! fetch "$BASE/$HOST.json" "$INV_BIN/$HOST.json"; then
        say "error: could not download $BASE/$HOST.json"
        exit 1
    fi
    chmod 700 "$INV_BIN/phylax" "$INV_BIN/$HOST.json" # inv:ro: our own downloaded copies under INV_BIN
    say "agent: install --bootstrap $INV_BIN/$HOST.json"
    if ! "$INV_BIN/phylax" agent install --bootstrap "$INV_BIN/$HOST.json"; then
        say "error: agent install failed"
        exit 1
    fi
fi

say "done: kit in $INV_KIT"
