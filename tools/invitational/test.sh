#!/bin/sh
# Harness for the Invitational collector scripts: syntax, read-only lint, then
# every test_*.sh. Prints PASS/FAIL and exits non-zero if anything failed.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1

. "$here/testlib.sh"

# Forbidden tokens. Any line that needs one must carry the marker "inv:ro"
# (the author asserts the use is read-only).
INV_SH_TOKENS='rm|mv|cp|chmod|chown|useradd|usermod|userdel|passwd|chpasswd|reboot|shutdown|halt|kill|pkill|killall|iptables|ip6tables|nft|ufw|systemctl|service|sed -i|crontab|visudo|mount|umount|sysctl -w|setenforce|auditctl|apt|apt-get|dnf|yum|pip|shadow' # inv:ro
INV_PS_PREFIX='Set|Remove|Restart|Stop|Disable|Enable|Add|Clear|Reset' # inv:ro
INV_PS_EXACT='New-ItemProperty|net user|net localgroup|reg add|reg delete|sc config|shutdown|/etc/shadow' # inv:ro
INV_SH_RE='(^|[^[:alnum:]_])('"$INV_SH_TOKENS"')([^[:alnum:]_]|$)'
INV_PS_RE="(^|[^[:alnum:]_-])(($INV_PS_PREFIX)-[A-Za-z]|$INV_PS_EXACT)"

inv_lint() {
    file=$1
    case $file in
        *.ps1) kind=ps ;;
        *) kind=sh ;;
    esac
    awk -v kind="$kind" -v shre="$INV_SH_RE" -v psre="$INV_PS_RE" '
        {
            if ($0 ~ /inv:ro/) next
            line = $0
            if (kind == "ps") {
                gsub(/Set-StrictMode/, "", line)
                if (line ~ /(Set-Content|Add-Content)/ && line ~ /(InvOut|InvRoot)/) {
                    gsub(/Set-Content/, "", line)
                    gsub(/Add-Content/, "", line)
                }
                if (line ~ psre) printf "%s:%d: %s\n", FILENAME, FNR, $0
            } else {
                if (line ~ shre) printf "%s:%d: %s\n", FILENAME, FNR, $0
            }
        }
    ' "$file"
}

syntax_ok=1
for f in "$here"/*.sh; do
    [ -f "$f" ] || continue
    if ! sh -n "$f"; then
        syntax_ok=0
    fi
done
if [ $syntax_ok -eq 1 ]; then
    t_pass sh-syntax
else
    t_fail sh-syntax "sh -n failed"
fi

lint_ok=1
for f in "$here"/*.sh "$here"/*.ps1; do
    [ -f "$f" ] || continue
    out=$(inv_lint "$f")
    if [ -n "$out" ]; then
        lint_ok=0
        printf 'FAIL lint: %s\n%s\n' "${f##*/}" "$out"
        _t_failed=$((_t_failed + 1))
    fi
done
if [ $lint_ok -eq 1 ]; then
    t_pass lint
else
    t_fail lint "forbidden token without inv:ro"
fi

if command -v pwsh >/dev/null 2>&1; then
    ps_ok=1
    for f in "$here"/*.ps1; do
        [ -f "$f" ] || continue
        if ! pwsh -NoProfile -Command "\$e = \$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$f',[ref]\$null,[ref]\$e); if(\$e){exit 1}" >/dev/null 2>&1; then
            ps_ok=0
            printf 'FAIL ps1-syntax: %s\n' "${f##*/}"
            _t_failed=$((_t_failed + 1))
        fi
    done
    if [ $ps_ok -eq 1 ]; then
        t_pass ps1-syntax
    else
        t_fail ps1-syntax "parse error"
    fi
else
    printf 'SKIP ps1-syntax (no pwsh)\n'
fi

for t in "$here"/test_*.sh; do
    [ -f "$t" ] || continue
    . "$t"
done

if [ "$_t_failed" -ne 0 ]; then
    exit 1
fi
exit 0
