# test_c1.sh -- C1 packet capture scripts. The dry run needs no root and no
# tcpdump; the live start path is exercised only on a capture host (Task 15).
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=$(mktemp -d)

out=$(INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start 2>&1)
assert_eq c1_dry_exit 0 $?
echo "$out" | grep -q -- '-s 1500' && echo "$out" | grep -q -- '-s 256' && echo "$out" | grep -q -- '-C 100 -W 20' && t_pass c1_cmdlines || t_fail c1_cmdlines "$out"
echo "$out" | grep -q 'not (port 21 or port 22' && t_pass c1_other_filter || t_fail c1_other_filter "$out"
SCORED_PORTS="8080 9090" INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start 2>&1 | grep -q 'port 8080 or port 9090' && t_pass c1_ports_override || t_fail c1_ports_override ""
INV_MIN_FREE_MB=99999999 INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start >/dev/null 2>&1; assert_eq c1_refuses_low_disk 1 $?
mkdir -p $T/r2/pcap; echo $$ > $T/r2/pcap/c1.pids
INV_DRY=1 INV_ROOT=$T/r2 sh "$HERE/c1-capture.sh" start >/dev/null 2>&1; assert_eq c1_refuses_second_start 1 $?
