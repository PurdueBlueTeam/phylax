#!/bin/sh
# c5-probe.sh [-t TARGETS_FILE] [-m MIRRORS_FILE] [-s https|http] [-p PORT]
# -- C5 reachability and internet probe (read only, connect-only).
#
# Answers E18 (which scored host:port is reachable from this host class) and E15
# (is the internet reachable, how fast, is TLS intercepted, what does the path
# look like). It opens TCP connections only, sends an unauthenticated WinRM
# OPTIONS and does HTTP GETs capped at 100 MB per host class: no payload reaches
# a scored port and nothing on the host is changed.
#
#   TARGETS_FILE  lines "host port [label]"; default is the 2027 scored set
#   MIRRORS_FILE  one hostname per line; default is the mirror list below
#   -s, -p        mirror scheme (https) and port (443, or 80 for http)
#
# Outputs in $INV_OUT: targets.txt, mirrors.txt, ports.csv, winrm.txt, http.csv,
# tls.txt, dns.csv, trace.txt, tools.txt, and one archive from inv_pack.

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$HERE/lib.sh"

SCHEME=https
MIRROR_PORT=
TARGETS_FILE=
MIRRORS_FILE=

usage() {
    printf 'usage: sh c5-probe.sh [-t TARGETS_FILE] [-m MIRRORS_FILE] [-s https|http] [-p PORT]\n'
}

# _default_targets: the scored services in the 2027 manifest.
_default_targets() {
    cat <<'EOF'
# Scored services in the 2027 manifest (manifest/2027/services.yml, scored: true)
# on the five LAN hosts. Regenerate from `phylax manifest load` when the team
# packet changes. ICMP checks have no port and are not probed here.
172.20.240.10 22 rocky-ecom-ssh
172.20.240.10 80 rocky-ecom-http
172.20.240.10 443 rocky-ecom-https
172.20.240.15 22 ubuntu-email-ssh
172.20.240.15 25 ubuntu-email-smtp
172.20.240.15 80 ubuntu-email-webmail
172.20.240.15 110 ubuntu-email-pop3
172.20.240.15 143 ubuntu-email-imap
172.20.240.20 22 debian-splunk-ssh
172.20.240.20 8000 debian-splunk-web
172.20.240.20 8089 debian-splunk-mgmt
172.20.240.100 53 ad-dns
172.20.240.100 5985 ad-winrm
172.20.240.120 445 mssql-smb
172.20.240.120 1433 mssql-sql
172.20.240.120 3389 mssql-rdp
EOF
}

# _default_mirrors: the E15 mirror list.
_default_mirrors() {
    cat <<'EOF'
# Internet mirrors from data question E15 (Debian, Ubuntu, Rocky, Microsoft,
# GitHub). One hostname per line.
deb.debian.org
archive.ubuntu.com
security.ubuntu.com
mirror.rockylinux.org
download.windowsupdate.com
github.com
EOF
}

# _rows FILE: the file without blank and comment lines.
_rows() {
    while IFS= read -r line; do
        case $line in
            ''|'#'*) continue ;;
        esac
        printf '%s\n' "$line"
    done < "$1"
}

# _inv_ms: the current time in milliseconds (seconds resolution if date has no %N).
_inv_ms() {
    ns=$(date +%s%N 2>/dev/null)
    case $ns in
        ''|*[!0-9]*) printf '%s000\n' "$(date +%s)" ;;
        *) printf '%s\n' "$((ns / 1000000))" ;;
    esac
}

# _probe_port HOST PORT: print "result ms exitcode". Connect only, 3 s bound.
_probe_port() {
    _ph=$1
    _pp=$2
    _pstart=$(_inv_ms)
    _pcode=127
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 3 "$_ph" "$_pp" >/dev/null 2>&1
        _pcode=$?
    elif command -v bash >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then
            timeout 3 bash -c ": </dev/tcp/$_ph/$_pp" >/dev/null 2>&1
        else
            # shortcut: no timeout(1), the connect can hang until the OS gives up
            bash -c ": </dev/tcp/$_ph/$_pp" >/dev/null 2>&1
        fi
        _pcode=$?
    fi
    _pend=$(_inv_ms)
    _pms=$((_pend - _pstart))
    [ "$_pms" -ge 0 ] || _pms=0

    if [ "$_pcode" -eq 0 ]; then
        _presult=open
    elif [ "$_pcode" -eq 124 ] || [ "$_pms" -ge 3000 ]; then
        _presult=timeout
    elif [ "$_pcode" -eq 127 ]; then
        # shortcut: no nc and no bash, no way to open a socket; keep the row visible
        _presult=error
    else
        _presult=closed
    fi
    printf '%s %s %s\n' "$_presult" "$_pms" "$_pcode"
}

# _mirror_url HOST: the URL the http probe fetches.
_mirror_url() {
    _mh=$1
    case $_mh in
        *:*) printf '%s://%s/\n' "$SCHEME" "$_mh" ;;
        *)
            case $SCHEME in
                http)
                    if [ "$MIRROR_PORT" = 80 ]; then
                        printf 'http://%s/\n' "$_mh"
                    else
                        printf 'http://%s:%s/\n' "$_mh" "$MIRROR_PORT"
                    fi
                    ;;
                *)
                    if [ "$MIRROR_PORT" = 443 ]; then
                        printf 'https://%s/\n' "$_mh"
                    else
                        printf 'https://%s:%s/\n' "$_mh" "$MIRROR_PORT"
                    fi
                    ;;
            esac
            ;;
    esac
}

# _tls_dump HOSTPORT NAME: issuer, subject and dates of one certificate.
_tls_dump() {
    _thp=$1
    _tname=$2
    _tcmd="echo | openssl s_client -connect '$_thp' -servername '$_tname' -showcerts"
    if command -v timeout >/dev/null 2>&1; then
        _tpem=$(timeout 10 sh -c "$_tcmd" 2>/dev/null)
    else
        _tpem=$(sh -c "$_tcmd" 2>/dev/null)
    fi
    if [ -z "$_tpem" ]; then
        printf 'no certificate (connect failed or no TLS on %s)\n' "$_thp"
        return 0
    fi
    printf '%s\n' "$_tpem" | openssl x509 -noout -issuer -subject -dates 2>&1
}

while [ $# -gt 0 ]; do
    case $1 in
        -t)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            TARGETS_FILE=$2
            shift 2
            ;;
        -m)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            MIRRORS_FILE=$2
            shift 2
            ;;
        -s)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            SCHEME=$2
            shift 2
            ;;
        -p)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            MIRROR_PORT=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'c5: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case $SCHEME in
    https|http) ;;
    *)
        printf 'c5: -s must be https or http, not %s\n' "$SCHEME" >&2
        exit 2
        ;;
esac
if [ -z "$MIRROR_PORT" ]; then
    case $SCHEME in
        http) MIRROR_PORT=80 ;;
        *) MIRROR_PORT=443 ;;
    esac
fi
case $MIRROR_PORT in
    ''|*[!0-9]*)
        printf 'c5: -p must be a port number, not %s\n' "$MIRROR_PORT" >&2
        exit 2
        ;;
esac

inv_init c5 || exit 1

if [ -n "$TARGETS_FILE" ] && [ -r "$TARGETS_FILE" ]; then
    cat "$TARGETS_FILE" > "$INV_OUT/targets.txt"
else
    [ -z "$TARGETS_FILE" ] || printf 'c5: cannot read %s, using the built-in targets\n' "$TARGETS_FILE" >&2
    _default_targets > "$INV_OUT/targets.txt"
fi
if [ -n "$MIRRORS_FILE" ] && [ -r "$MIRRORS_FILE" ]; then
    cat "$MIRRORS_FILE" > "$INV_OUT/mirrors.txt"
else
    [ -z "$MIRRORS_FILE" ] || printf 'c5: cannot read %s, using the built-in mirrors\n' "$MIRRORS_FILE" >&2
    _default_mirrors > "$INV_OUT/mirrors.txt"
fi

# Which tools this host has: a missing one is a recorded gap, not an abort.
tools="$INV_OUT/tools.txt"
: > "$tools"
for t in nc bash curl openssl traceroute tracepath getent timeout; do
    p=$(command -v "$t" 2>/dev/null)
    printf '%s %s\n' "$t" "${p:-missing}" >> "$tools"
done

# ports.csv: every target, connect only, 3 s bound.
ports="$INV_OUT/ports.csv"
printf 'host,port,result,ms\n' > "$ports"
_rows "$INV_OUT/targets.txt" | while read -r host port label; do
    [ -n "$host" ] || continue
    case $port in
        ''|*[!0-9]*) continue ;;
    esac
    set -- $(_probe_port "$host" "$port")
    printf '%s,%s,%s,%s\n' "$host" "$port" "$1" "$2" >> "$ports"
done

# winrm.txt: the unauthenticated OPTIONS exchange for WinRM targets (E18).
winrm="$INV_OUT/winrm.txt"
: > "$winrm"
if _rows "$INV_OUT/targets.txt" | awk '$2 == 5985 || $2 == 5986 { found = 1 } END { exit !found }'; then
    _rows "$INV_OUT/targets.txt" | while read -r host port label; do
        case $port in
            5985|5986) ;;
            *) continue ;;
        esac
        case $port in
            5986) url="https://$host:$port/wsman" ;;
            *) url="http://$host:$port/wsman" ;;
        esac
        printf '== %s ==\n' "$url" >> "$winrm"
        if command -v curl >/dev/null 2>&1; then
            if [ "$port" = 5986 ]; then
                # -k: lab WinRM certs are self-signed; only the headers are read
                curl -sS -k -m 5 -i -X OPTIONS "$url" >> "$winrm" 2>&1
            else
                curl -sS -m 5 -i -X OPTIONS "$url" >> "$winrm" 2>&1
            fi
            printf '\n' >> "$winrm"
        else
            printf 'curl: not found\n' >> "$winrm"
        fi
    done
else
    printf 'no WinRM target (5985/5986) in %s\n' "$INV_OUT/targets.txt" >> "$winrm"
fi

# http.csv: one capped GET per mirror, with the timing split curl reports.
http="$INV_OUT/http.csv"
printf 'url,code,dns_s,connect_s,tls_s,total_s,bytes\n' > "$http"
_rows "$INV_OUT/mirrors.txt" | while read -r mirror; do
    [ -n "$mirror" ] || continue
    url=$(_mirror_url "$mirror")
    if command -v curl >/dev/null 2>&1; then
        row=$(curl -o /dev/null -s --max-filesize 104857600 -m 60 \
            -w '%{http_code},%{time_namelookup},%{time_connect},%{time_appconnect},%{time_total},%{size_download}' \
            "$url" 2>/dev/null)
    else
        row=
    fi
    [ -n "$row" ] || row='000,0,0,0,0,0'
    printf '%s,%s\n' "$url" "$row" >> "$http"
done

# tls.txt: is there a proxy or TLS interception (E15)?
tls="$INV_OUT/tls.txt"
: > "$tls"
{
    printf 'github.com\n'
    _rows "$INV_OUT/mirrors.txt"
} | sort -u | while read -r name; do
    [ -n "$name" ] || continue
    case $name in
        *:*) hp=$name ;;
        *) hp="$name:443" ;;
    esac
    printf '== %s ==\n' "$hp" >> "$tls"
    if command -v openssl >/dev/null 2>&1; then
        _tls_dump "$hp" "$name" >> "$tls"
    else
        printf 'openssl: not found\n' >> "$tls"
    fi
done

# dns.csv: resolution time per mirror name and github.com (E15).
dns="$INV_OUT/dns.csv"
printf 'name,ms\n' > "$dns"
{
    printf 'github.com\n'
    _rows "$INV_OUT/mirrors.txt"
} | sort -u | while read -r name; do
    [ -n "$name" ] || continue
    case $name in
        *:*) name=${name%%:*} ;;
    esac
    if command -v getent >/dev/null 2>&1; then
        start=$(_inv_ms)
        getent hosts "$name" >/dev/null 2>&1
        end=$(_inv_ms)
        printf '%s,%s\n' "$name" "$((end - start))" >> "$dns"
    else
        # shortcut: no getent, resolution time is recorded as -1 (unmeasured)
        printf '%s,-1\n' "$name" >> "$dns"
    fi
done

# trace.txt: the path to the first mirror, bounded to 15 hops.
first=$(_rows "$INV_OUT/mirrors.txt" | head -n 1)
if [ -z "$first" ]; then
    printf 'trace: no mirror to trace\n' > "$INV_OUT/trace.txt"
elif command -v tracepath >/dev/null 2>&1; then
    # tracepath first: the inetutils traceroute on Ubuntu has no -n.
    inv_run trace tracepath -n -m 15 "$first"
elif command -v traceroute >/dev/null 2>&1; then
    inv_run trace traceroute -n -w 2 -m 15 "$first"
else
    printf 'trace: neither traceroute nor tracepath\n' > "$INV_OUT/trace.txt"
fi

inv_pack
