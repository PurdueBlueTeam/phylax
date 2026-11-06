# test_c6.sh -- C6 ops timeline marker, C7 scribe sheet and the O2 checklist.
# The scripts are pure text handling, so the whole test is local.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=$(mktemp -d)

INV_ROOT=$T/r sh "$HERE/m.sh" drop flag; INV_ROOT=$T/r sh "$HERE/m.sh" console open rocky
assert_eq c6_two_lines 2 "$(wc -l < $T/r/timeline.txt)"
assert_grep c6_format "^20..-..-..T..:..:..Z	$(hostname -s)	drop flag$" $T/r/timeline.txt
assert_grep c6_second_line "console open rocky" $T/r/timeline.txt
# m.ps1 runs where pwsh does (this VM has no Windows host); the line format is
# the same one m.sh writes.
if command -v pwsh >/dev/null 2>&1; then
    INV_TIMELINE=$T/ptimeline.txt pwsh -NoProfile -File "$HERE/m.ps1" drop flag >/dev/null 2>&1
    assert_grep c6_ps1_format "^20..-..-..T..:..:..Z	.*	drop flag$" $T/ptimeline.txt
else
    printf 'SKIP c6_ps1 (no pwsh)\n'
fi
(cd $T && sh "$HERE/scribe.sh" init && sh "$HERE/scribe.sh" init && sh "$HERE/scribe.sh" row http up 120 "round 1")
assert_eq c6_scribe_header_once 1 "$(grep -c '^utc,' $T/scribe.csv)"
assert_grep c6_scribe_row ",round 1,http,up,120," $T/scribe.csv
assert_grep c6_o2_items "keys that do not map" "$HERE/o2-checklist.txt"

# The two C7 records without a board row: the S13 submit time and the S14
# credlist snapshot the scribe saved from the PCR tab.
(cd $T && sh "$HERE/scribe.sh" pcr 30)
assert_grep c6_scribe_pcr "^20..-..-..T..:..:..Z	30$" $T/pcr.txt
printf '{"lists":[{"name":"web","users":["alice"]}]}\n' > $T/credlists.json
(cd $T && sh "$HERE/scribe.sh" credlists credlists.json) >/dev/null 2>&1; assert_eq c6_scribe_credlists_exit 0 $?
SNAP=$(ls $T/credlists-*.json 2>/dev/null | head -1); assert_file c6_scribe_credlists "$SNAP"
assert_grep c6_scribe_credlists_body '"name":"web"' "$SNAP"
if (cd $T && sh "$HERE/scribe.sh" credlists missing.json) >/dev/null 2>&1; then
    t_fail c6_scribe_credlists_missing "a missing file was accepted"
else
    t_pass c6_scribe_credlists_missing
fi
