# test_c3.sh -- C3 log bulk copy. The set of logs is small and made here; the
# real run happens on the event hosts (Task 15).
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=$(mktemp -d)

mkdir -p $T/log/apache2 $T/log/audit $T/splunk
echo a > $T/log/auth.log; echo b > $T/log/apache2/access.log; echo c > $T/log/audit/audit.log; echo d > $T/splunk/splunkd.log; echo e > $T/log/unrelated.bin
LOGROOT=$T/log SPLUNK_LOGS=$T/splunk INV_ROOT=$T/r sh "$HERE/c3-logs.sh" mid >/dev/null 2>&1; assert_eq c3_exit 0 $?
a=$(ls $T/r/*c3-mid*.tar.gz | head -1); assert_file c3_archive "$a"
for f in auth.log apache2/access.log audit/audit.log splunkd.log; do tar tzf "$a" | grep -q "$f" && t_pass "c3_has_$(basename $f)" || t_fail "c3_has_$(basename $f)" "not archived"; done
tar tzf "$a" | grep -q unrelated.bin && t_fail c3_only_listed "unrelated file archived" || t_pass c3_only_listed
LOGROOT=$T/nothing INV_ROOT=$T/r5 sh "$HERE/c3-logs.sh" end >/dev/null 2>&1; assert_eq c3_empty_logroot_exit 0 $?
INV_MAX_FILE_MB=0 LOGROOT=$T/log INV_ROOT=$T/r6 sh "$HERE/c3-logs.sh" mid >/dev/null 2>&1; grep -q 'skipped' $T/r6/*/c3-*/files.txt && t_pass c3_size_skip || t_fail c3_size_skip "no skipped line"
