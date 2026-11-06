# test_lib.sh
T=$(mktemp -d); export INV_ROOT=$T/root
. "$(dirname "$0")/lib.sh"
inv_init demo
assert_file lib_meta "$INV_OUT/_meta.txt"
assert_grep lib_meta_host "$(hostname -s)" "$INV_OUT/_meta.txt"
inv_run echo1 echo hello
inv_run missing_cmd no-such-command-xyz
assert_grep lib_run_out hello "$INV_OUT/echo1.txt"
assert_grep lib_index_ok "^echo1	0	" "$INV_OUT/_index.tsv"
assert_grep lib_index_127 "^missing_cmd	127	" "$INV_OUT/_index.tsv"
set -- $(inv_pack); assert_file lib_pack "$1"
tar tzf "$1" | grep -q "echo1.txt" && t_pass lib_pack_has_file || t_fail lib_pack_has_file "echo1.txt not in archive"
case $(inv_utc) in 20??-??-??T??:??:??Z) t_pass lib_utc ;; *) t_fail lib_utc "$(inv_utc)" ;; esac
inv_init demo; assert_eq lib_dirs_distinct 2 "$(ls "$INV_ROOT/$INV_HOST" | wc -l)"   # same CID, same second: second dir gets a suffix
