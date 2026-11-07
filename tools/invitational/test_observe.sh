# test_observe.sh -- make-observe-manifest.sh drops the capture role from every
# host and the copied capture module block, for every roles list shape.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=$(mktemp -d)

# A synthetic source manifest with each roles list shape (the 2027 manifest has
# only some of them), plus a capture module block and a sibling module block.
S=$T/src
mkdir -p "$S/modules"
cat > "$S/policy.yml" <<'EOF'
canary_ports: [21, 22]
EOF
cat > "$S/hosts.yml" <<'EOF'
hosts:
  only:   { roles: [capture] }
  first:  { roles: [capture, decoys] }
  last:   { roles: [decoys, capture] }
  middle: { roles: [check_runner, capture, scanner] }
  other:  { roles: [decoys] }
EOF
printf 'enabled: true\n' > "$S/modules/capture.yml"
printf 'enabled: true\n' > "$S/modules/suricata.yml"

sh "$HERE/make-observe-manifest.sh" "$S" "$T/obs" >/dev/null 2>&1
assert_eq observe_exit 0 $?
assert_grep observe_only "only:.*roles: \[\]" "$T/obs/hosts.yml"
assert_grep observe_first "first:.*roles: \[decoys\]" "$T/obs/hosts.yml"
assert_grep observe_last "last:.*roles: \[decoys\]" "$T/obs/hosts.yml"
assert_grep observe_middle "middle:.*roles: \[check_runner, scanner\]" "$T/obs/hosts.yml"
assert_grep observe_other "other:.*roles: \[decoys\]" "$T/obs/hosts.yml"
if grep -q capture "$T/obs/hosts.yml"; then
    t_fail observe_no_capture_role "$(grep capture "$T/obs/hosts.yml")"
else
    t_pass observe_no_capture_role
fi
if [ -e "$T/obs/modules/capture.yml" ] || [ -e "$T/obs/capture.yml" ]; then
    t_fail observe_drops_capture_yml "capture.yml copied"
else
    t_pass observe_drops_capture_yml
fi
assert_file observe_keeps_other_module "$T/obs/modules/suricata.yml"
assert_grep observe_canary_off "canary_ports: \[\]" "$T/obs/policy.yml"
assert_grep observe_src_untouched "only:   { roles: \[capture\] }" "$S/hosts.yml"

# --no-decoys composes with the capture removal.
sh "$HERE/make-observe-manifest.sh" "$S" "$T/obs2" --no-decoys >/dev/null 2>&1
assert_eq observe_nodecoys_exit 0 $?
assert_grep observe_nodecoys_first "first:.*roles: \[\]" "$T/obs2/hosts.yml"
assert_grep observe_nodecoys_last "last:.*roles: \[\]" "$T/obs2/hosts.yml"
assert_grep observe_nodecoys_middle "middle:.*roles: \[check_runner, scanner\]" "$T/obs2/hosts.yml"

# The real 2027 manifest, as the runbook invokes it.
sh "$HERE/make-observe-manifest.sh" "$HERE/../../manifest/2027" "$T/obs2027" >/dev/null 2>&1
assert_eq observe_2027_exit 0 $?
assert_grep observe_2027_ad "ad:.*roles: \[check_runner, domain_controller\]" "$T/obs2027/hosts.yml"
assert_grep observe_2027_wkst "ubuntu-wkst:.*roles: \[controller, check_runner\]" "$T/obs2027/hosts.yml"
if grep -q capture "$T/obs2027/hosts.yml"; then
    t_fail observe_2027_no_capture_role "$(grep capture "$T/obs2027/hosts.yml")"
else
    t_pass observe_2027_no_capture_role
fi
