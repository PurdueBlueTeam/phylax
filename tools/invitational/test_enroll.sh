# test_enroll.sh -- console enrollment script e.sh against a throwaway web root.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1

if ! command -v python3 >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    printf 'SKIP enroll (needs python3 and curl)\n'
else
    TE=$(mktemp -d)
    WEB=$TE/web
    mkdir -p "$WEB"

    # The kit archive the controller serves: the top directory is "invitational".
    tar czf "$WEB/kit.tgz" -C "$HERE/.." invitational

    # A stub agent binary (fixture, not the code under test): records its arguments.
    cat > "$WEB/phylax" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$TE/args"
EOF
    chmod 700 "$WEB/phylax" # inv:ro: our own test fixture
    printf '{}\n' > "$WEB/h1.json"

    PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
    python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WEB" >"$TE/server.log" 2>&1 &
    SRV=$!
    trap 'kill $SRV 2>/dev/null' EXIT # inv:ro: stops our own test server

    tries=0
    while [ "$tries" -lt 50 ]; do
        if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/kit.tgz" 2>/dev/null; then
            break
        fi
        tries=$((tries + 1))
        sleep 0.2
    done

    INV_KIT=$TE/kit INV_BIN=$TE/bin sh "$HERE/e.sh" "127.0.0.1:$PORT" h1 agent >"$TE/out" 2>&1
    assert_eq enroll_exit 0 $?
    assert_file enroll_kit "$TE/kit/invitational/lib.sh"
    assert_grep enroll_args "agent install --bootstrap $TE/bin/h1.json" "$TE/args"
    assert_grep enroll_utc "^20..-..-..T..:..:..Z" "$TE/out"

    # No "agent": the kit only, no binary.
    INV_KIT=$TE/kit2 INV_BIN=$TE/bin2 sh "$HERE/e.sh" "127.0.0.1:$PORT" h1 >/dev/null 2>&1
    if [ -e "$TE/bin2/phylax" ]; then
        t_fail enroll_kit_only "binary fetched"
    else
        t_pass enroll_kit_only
    fi

    # No arguments: usage on stderr, non-zero exit.
    if sh "$HERE/e.sh" >"$TE/usage.out" 2>&1; then
        t_fail enroll_usage_exit "no arguments did not fail"
    else
        t_pass enroll_usage_exit
    fi
    if grep -qi usage "$TE/usage.out"; then
        t_pass enroll_usage_msg
    else
        t_fail enroll_usage_msg "$(cat "$TE/usage.out")"
    fi

    kill "$SRV" 2>/dev/null # inv:ro: stops our own test server
    wait "$SRV" 2>/dev/null
    trap - EXIT
fi
