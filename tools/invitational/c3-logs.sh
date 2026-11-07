#!/bin/sh
# c3-logs.sh [LABEL] -- C3 log bulk copy (read only).
#
# Copies the logs offline analysis needs (data doc C3: auth, syslog, mail, web,
# FTP, Dovecot, auditd, package manager and Splunk) at mid-event and at the end.
# One timestamped directory of listings plus one archive; nothing on the host is
# changed. Files over INV_MAX_FILE_MB (default 1024, the plan's 1 GB cap) are
# recorded as skipped and left out of the archive.
#
# Usage: sh c3-logs.sh [mid|end]

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$HERE/lib.sh"

LABEL=${1:-mid}
LOGROOT=${LOGROOT:-/var/log}
SPLUNK_LOGS=${SPLUNK_LOGS:-/opt/splunk/var/log/splunk}
INV_MAX_FILE_MB=${INV_MAX_FILE_MB:-1024}
export LOGROOT SPLUNK_LOGS INV_MAX_FILE_MB

inv_init "c3-$LABEL" || exit 1

LOGPATHS='auth.log* secure* syslog* messages* mail.log* maillog* kern.log* apache2 httpd nginx vsftpd.log* dovecot* proftpd audit/audit.log* mysql mariadb cron* dpkg.log* yum.log* dnf.log*' # inv:ro: log file names only, they are read

files="$INV_OUT/files.txt"
list="$INV_OUT/.files.lst"
: > "$files"
: > "$list"

max_bytes=$((INV_MAX_FILE_MB * 1024 * 1024))

# Absolute path of $1, for the tar list below (tar is run with -C /).
_abs() {
    case $1 in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$(pwd)" "$1" ;;
    esac
}

# _add_file PATH: list one file, unless it is over the size cap.
_add_file() {
    file=$1
    size=$(stat -c %s "$file" 2>/dev/null)
    [ -n "$size" ] || size=$(wc -c < "$file" 2>/dev/null)
    [ -n "$size" ] || size=0
    listing=$(ls -l "$file" 2>&1)

    if [ "$size" -gt "$max_bytes" ]; then
        # E17/disk fill: the size cap keeps one huge log from filling the VM.
        printf 'skipped (over %s MB): %s\n' "$INV_MAX_FILE_MB" "$listing" >> "$files"
        return 0
    fi
    printf '%s\n' "$listing" >> "$files"
    abs=$(_abs "$file")
    printf '%s\n' "${abs#/}" >> "$list"
}

# _add_path PATH: a file is listed as is, a directory is listed and walked.
_add_path() {
    path=$1
    if [ -d "$path" ]; then
        printf '%s\n' "$(ls -ld "$path" 2>&1)" >> "$files"
        find "$path" -type f 2>/dev/null | while IFS= read -r f; do
            _add_file "$f"
        done
    elif [ -f "$path" ]; then
        _add_file "$path"
    fi
}

for pat in $LOGPATHS; do
    for path in "$LOGROOT"/$pat; do
        [ -e "$path" ] || continue
        _add_path "$path"
    done
done

for path in "$SPLUNK_LOGS"/splunkd*.log*; do
    [ -e "$path" ] || continue
    _add_path "$path"
done

archive="$INV_ROOT/$INV_HOST-c3-$LABEL-$INV_STAMP.tar.gz"
n=1
while [ -e "$archive" ]; do
    n=$((n + 1))
    archive="$INV_ROOT/$INV_HOST-c3-$LABEL-$INV_STAMP-$n.tar.gz"
done

if [ -s "$list" ]; then
    tar -czf "$archive" -C / -T "$list" -C "$INV_OUT" files.txt
else
    # Nothing in the set exists (or all of it was over the cap): still ship the
    # listing so the gap is visible.
    tar -czf "$archive" -C "$INV_OUT" files.txt
fi
code=$?
# tar exits 1 when a live log grew while it was read: the archive is still good.
if [ $code -eq 1 ]; then
    printf 'c3: some files changed while archiving (tar exit 1), archive kept\n' >&2
    code=0
fi
if [ $code -ne 0 ]; then
    printf 'c3: archive failed (tar exit %s): %s\n' "$code" "$archive" >&2
    exit $code
fi

bytes=$(wc -c < "$archive" | tr -d '[:space:]')
if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$archive" | cut -d' ' -f1)
else
    sum=$(shasum -a 256 "$archive" | cut -d' ' -f1)
fi
printf '%s %s %s\n' "$archive" "$bytes" "$sum"
