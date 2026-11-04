set -u

NS=tba
EVIL=tbaevil
BR=tbabr0
IF=tba0
EVIF=tbae0
NET=10.78.0
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIARP=$ROOT/build/test/tundra-blueice-arp
TOOLS=$ROOT/build/test/tools
WORK=$(mktemp -d /tmp/tba-test.XXXXXX)
OUT=$WORK/out
ERR=$WORK/err
HISTORY=/run/tundra/blueice/arp
ADDR=$NET.10

PASS=0
FAIL=0
RUN_EXIT=
RUN_PID=
HELPER_PID=

ok() {
	PASS=$((PASS + 1))
	printf 'ok - %s\n' "$1"
}

not_ok() {
	FAIL=$((FAIL + 1))
	printf 'not ok - %s\n' "$1"
}

check() {
	desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		ok "$desc"
	else
		not_ok "$desc"
	fi
}

eventually() {
	desc=$1
	n=$(($2 * 10))
	shift 2
	while [ "$n" -gt 0 ]; do
		if "$@" >/dev/null 2>&1; then
			ok "$desc"
			return 0
		fi
		sleep 0.1
		n=$((n - 1))
	done
	not_ok "$desc"
}

dump() {
	sed 's/^/#   out: /' "$OUT"
	sed 's/^/#   err: /' "$ERR"
}

expect_exit() {
	if [ "$RUN_EXIT" = "$1" ]; then
		ok "$2"
	else
		not_ok "$2 (exit $RUN_EXIT)"
		dump
	fi
}

expect_out() {
	if grep -q -- "$1" "$OUT"; then
		ok "$2"
	else
		not_ok "$2"
		dump
	fi
}

expect_err() {
	if grep -q -- "$1" "$ERR"; then
		ok "$2"
	else
		not_ok "$2"
		dump
	fi
}

in_ns() {
	ip netns exec "$NS" "$@"
}

in_evil() {
	ip netns exec "$EVIL" "$@"
}

evil_mac() {
	in_evil cat "/sys/class/net/$EVIF/address"
}

claim() {
	in_evil "$TOOLS/arpsend" "$EVIF" "$@"
}

run() {
	in_ns "$BIARP" "$@" >"$OUT" 2>"$ERR"
	RUN_EXIT=$?
}

run_bg() {
	ip netns exec "$NS" "$BIARP" "$@" >"$OUT" 2>"$ERR" &
	RUN_PID=$!
}

start_helper() {
	ip netns exec "$EVIL" "$@" &
	HELPER_PID=$!
}

wait_run() {
	wait "$RUN_PID"
	RUN_EXIT=$?
	RUN_PID=
}

probe() {
	run probe "$IF" "$@"
}

start_watch() {
	run_bg watch "$IF" addr "$ADDR" "$@"
}

stop_watch() {
	kill -TERM "$RUN_PID" 2>/dev/null
	wait_run
}

wait_out() {
	n=$(($2 * 10))
	while [ "$n" -gt 0 ]; do
		grep -q -- "$1" "$OUT" 2>/dev/null && return 0
		sleep 0.1
		n=$((n - 1))
	done
	return 1
}

expect_out_in() {
	if wait_out "$1" "$2"; then
		ok "$3"
	else
		not_ok "$3"
		dump
	fi
}

wait_exit() {
	n=$(($1 * 10))
	while kill -0 "$RUN_PID" 2>/dev/null; do
		[ "$n" -le 0 ] && return 1
		sleep 0.1
		n=$((n - 1))
	done
	wait_run
	return 0
}

running() {
	kill -0 "$RUN_PID" 2>/dev/null
}

err_lines() {
	[ "$(grep -c -- "$1" "$ERR")" -eq "$2" ]
}

reset_history() {
	rm -f "$HISTORY/$IF" "$HISTORY/$IF.lock" "$HISTORY/$IF.tmp"
}

stop_helper() {
	if [ -n "$HELPER_PID" ]; then
		kill "$HELPER_PID" 2>/dev/null
		wait "$HELPER_PID" 2>/dev/null
		HELPER_PID=
	fi
}

kill_ns() {
	for pid in $(ip netns pids "$1" 2>/dev/null); do
		kill "$pid" 2>/dev/null
	done
	ip netns del "$1" 2>/dev/null
}

teardown_net() {
	stop_helper
	if [ -n "$RUN_PID" ]; then
		kill "$RUN_PID" 2>/dev/null
		wait "$RUN_PID" 2>/dev/null
		RUN_PID=
	fi
	kill_ns "$NS"
	kill_ns "$EVIL"
	ip link del "${IF}p" 2>/dev/null
	ip link del "${EVIF}p" 2>/dev/null
	ip link del "$BR" 2>/dev/null
	reset_history
	return 0
}

setup() {
	teardown_net
	ip link add "$BR" type bridge
	ip addr add "$NET.1/24" dev "$BR"
	ip link set "$BR" up
	ip netns add "$NS"
	ip link add "$IF" type veth peer name "${IF}p"
	ip link set "$IF" netns "$NS"
	ip link set "${IF}p" master "$BR" up
	in_ns ip link set lo up
	in_ns ip link set "$IF" up
	ip netns add "$EVIL"
	ip link add "$EVIF" type veth peer name "${EVIF}p"
	ip link set "$EVIF" netns "$EVIL"
	ip link set "${EVIF}p" master "$BR" up
	in_evil ip link set "$EVIF" up
	in_ns ip addr add "$ADDR/24" dev "$IF"
}

teardown() {
	teardown_net
	rm -rf "$WORK"
}

summary() {
	printf '# %d passed, %d failed\n' "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}

trap teardown EXIT
trap 'exit 130' INT TERM
