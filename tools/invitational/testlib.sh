#!/bin/sh
# Minimal assertion helpers for the collector test harness.

_t_failed=${_t_failed:-0}

t_pass() {
    printf 'PASS %s\n' "$1"
}

t_fail() {
    printf 'FAIL %s: %s\n' "$1" "$2"
    _t_failed=$((_t_failed + 1))
}

assert_eq() {
    name=$1
    expected=$2
    actual=$3
    if [ "$expected" = "$actual" ]; then
        t_pass "$name"
    else
        t_fail "$name" "expected [$expected], got [$actual]"
    fi
}

assert_file() {
    name=$1
    path=$2
    if [ -s "$path" ]; then
        t_pass "$name"
    else
        t_fail "$name" "missing or empty: $path"
    fi
}

assert_grep() {
    name=$1
    pattern=$2
    path=$3
    if [ ! -f "$path" ]; then
        t_fail "$name" "missing file: $path"
    elif grep -q -- "$pattern" "$path"; then
        t_pass "$name"
    else
        t_fail "$name" "pattern [$pattern] not found in $path"
    fi
}
