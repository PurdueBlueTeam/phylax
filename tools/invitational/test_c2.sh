# test_c2.sh -- C2 Linux host facts and the resource sampler.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=${T:-$(mktemp -d)}

INV_ROOT=$T/r sh "$HERE/c2-facts.sh" >"$T/c2.out" 2>&1
assert_eq c2_exit 0 $?

idx=$(ls -d $T/r/*/c2-*/ | head -1)_index.tsv
for n in kernel procversion btf kconfig osrelease packages versions containers \
    listeners unixsockets group sudoers lastlog authkeys cron timers units \
    auditstate auditd logconf journal firewall network disk memory cpu boot ntp \
    sshd mail web splunk datasizes passwd; do # inv:ro: record names only, read with getent
    grep -q "^$n	" "$idx" && t_pass c2_has_$n || t_fail c2_has_$n "missing from _index.tsv"
done

assert_file c2_osrelease "$(dirname "$idx")/osrelease.txt"

ls $T/r/*.tar.gz >/dev/null 2>&1 && t_pass c2_archive || t_fail c2_archive "no tar.gz"

# Account lines carry x, never a hash: no hash-like line anywhere in the run.
grep -rE '^[a-z_-]+:\$[0-9a-z]+\$' "$T/r" >/dev/null 2>&1 && t_fail c2_no_hashes "hash-like line collected" || t_pass c2_no_hashes

# Runs with a minimal PATH: missing tools record their exit code and the
# collector still finishes.
PATH=/usr/bin:/bin INV_ROOT=$T/r3 sh "$HERE/c2-facts.sh" >/dev/null 2>&1
assert_eq c2_minimal_path_exit 0 $?

INV_SAMPLE_ONCE=1 INV_ROOT=$T/r4 sh "$HERE/c2-sampler.sh" start
assert_eq c2_sampler_rows 2 "$(wc -l < $T/r4/sampler.csv)"
assert_grep c2_sampler_header '^utc,load1,mem_avail_kb,root_used_pct,cpu_busy_pct$' $T/r4/sampler.csv
