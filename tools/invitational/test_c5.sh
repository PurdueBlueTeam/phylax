# test_c5.sh -- C5 reachability and internet probe. A local python server stands
# in for one scored port and for a mirror; the real probe runs on the event hosts
# (Task 15). The probe is connect-only, so the test only checks that it records
# what it saw.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
T=$(mktemp -d)

if ! command -v python3 >/dev/null 2>&1; then
    printf 'SKIP c5 (no python3 to serve the test page)\n'
    return 0
fi
if ! command -v nc >/dev/null 2>&1; then
    printf 'SKIP c5 (no nc to pick a free port)\n'
    return 0
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'SKIP c5 (no curl to measure a mirror)\n'
    return 0
fi

# pick_port: a port on loopback with nothing listening right now.
pick_port() {
    p=$((20000 + ($$ % 20000)))
    while nc -z -w 1 127.0.0.1 "$p" >/dev/null 2>&1; do
        p=$((p + 1))
    done
    printf '%s\n' "$p"
}

# The server binds port 0 and prints the port it got: choosing a port first
# and binding it afterwards races another process under load.
mkdir -p "$T/site"
head -c 1000 /dev/zero | tr '\0' 'x' > "$T/site/index.html"
(cd "$T/site" && exec python3 -u -m http.server 0 --bind 127.0.0.1) >"$T/server.log" 2>&1 &
py=$!
PORT=
i=0
while [ "$i" -lt 100 ]; do
    PORT=$(sed -n 's/.* port \([0-9][0-9]*\) .*/\1/p' "$T/server.log" | head -n 1)
    [ -n "$PORT" ] && break
    sleep 0.1
    i=$((i + 1))
done
if [ -z "$PORT" ]; then
    t_fail c5_server "the test server printed no port: $(cat "$T/server.log")"
    kill $py 2>/dev/null # inv:ro: stops only this test's own python server
    return 0
fi
DEAD=$(pick_port)

printf '127.0.0.1 %s web\n127.0.0.1 %s dead\n' "$PORT" "$DEAD" >"$T/targets"
printf '127.0.0.1\n' >"$T/mirrors"
INV_ROOT=$T/r sh "$HERE/c5-probe.sh" -t "$T/targets" -m "$T/mirrors" -p "$PORT" -s http >/dev/null 2>&1; assert_eq c5_exit 0 $?
d=$(ls -d $T/r/*/c5-*/ | head -1)
assert_grep c5_open "^127.0.0.1,$PORT,open," "$d/ports.csv"
assert_grep c5_closed "^127.0.0.1,$DEAD,closed," "$d/ports.csv"
assert_grep c5_http_row "^http://127.0.0.1:$PORT/,200," "$d/http.csv"
assert_eq c5_bytes_1000 1000 "$(awk -F, '$1 ~ /^http:/ { print $7 }' "$d/http.csv" | head -1)"

kill $py 2>/dev/null # inv:ro: stops only this test's own python server
wait $py 2>/dev/null
