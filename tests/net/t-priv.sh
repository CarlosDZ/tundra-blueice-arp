. "$(dirname "$0")/lib.sh"

# A copy inside the build directory: /tmp is usually nosuid and the test
# binary is rebuilt, losing its capability, on every run.
CAPBIN=$ROOT/build/test/tundra-blueice-arp.caps
BLUEICE=/run/tundra/blueice
TUSER=$(stat -c %U "$ROOT")
[ "$(id -u "$TUSER")" -eq 0 ] && TUSER=nobody
TUID=$(id -u "$TUSER")
TGID=$(id -g "$TUSER")
OWN_BLUEICE=
OWN_HISTORY=

status_is() {
	grep -q "^$1:[[:space:]]*$2\$" "/proc/$RUN_PID/status"
}

no_caps() {
	for set in CapInh CapPrm CapEff CapAmb; do
		status_is "$set" 0000000000000000 || return 1
	done
}

expect_locked() {
	eventually "$1: seccomp filter loaded" 3 status_is Seccomp 2
	check "$1: no_new_privs set" status_is NoNewPrivs 1
	check "$1: no capabilities left" no_caps
}

as_user() {
	inh=$1
	shift
	ip netns exec "$NS" setpriv --reuid "$TUID" --regid "$TGID" \
		--clear-groups --inh-caps "$inh" "$CAPBIN" "$@"
}

user_run() {
	as_user "$@" >"$OUT" 2>"$ERR"
	RUN_EXIT=$?
}

user_run_bg() {
	as_user "$@" >"$OUT" 2>"$ERR" &
	RUN_PID=$!
}

priv_teardown() {
	rm -f "$CAPBIN"
	reset_history
	[ -n "$OWN_HISTORY" ] && chown "$OWN_HISTORY" "$HISTORY"
	[ -n "$OWN_BLUEICE" ] && chown "$OWN_BLUEICE" "$BLUEICE"
	teardown
}
trap priv_teardown EXIT

setup
GWMAC=$(cat "/sys/class/net/$BR/address")
EVMAC=02:aa:aa:aa:aa:01

start_watch gw "$NET.1"
expect_out_in "^gateway is at $GWMAC$" 5 "root watch: watching"
expect_locked "root watch"
stop_watch
expect_exit 0 "root watch: SIGTERM exits with 0"

run_bg probe "$IF" "$NET.50"
expect_locked "root probe"
wait_run
expect_exit 0 "root probe: completes"

reset_history
mkdir -p "$HISTORY"
OWN_BLUEICE=$(stat -c %u:%g "$BLUEICE")
OWN_HISTORY=$(stat -c %u:%g "$HISTORY")
chown "$TUID:$TGID" "$BLUEICE" "$HISTORY"
cp "$BIARP" "$CAPBIN"
setcap cap_net_raw+ei "$CAPBIN"
if findmnt -no OPTIONS -T "$CAPBIN" | grep -qw nosuid; then
	echo "# $ROOT is mounted nosuid: file capabilities are ignored"
fi

user_run +net_raw probe "$IF" "$NET.50"
expect_exit 0 "inheritable: probe completes as $TUSER"
expect_out "^free$" "inheritable: probe reports"

in_evil ip addr add "$NET.60/24" dev "$EVIF"
user_run +net_raw probe "$IF" "$NET.60"
expect_exit 0 "inheritable: probe finds the address in use"
check "inheritable: the history is written" test -s "$HISTORY/$IF"

user_run_bg +net_raw watch "$IF" addr "$ADDR" gw "$NET.1"
expect_out_in "^gateway is at $GWMAC$" 5 "inheritable: watch learns the gateway"
check "inheritable: watch runs as $TUSER" status_is Uid "$TUID[[:space:]].*"
expect_locked "inheritable watch"
claim "$EVMAC" "$ADDR" "$ADDR"
expect_out_in "^defending address $ADDR against $EVMAC$" 3 "inheritable: watch defends the address"
stop_watch
expect_exit 0 "inheritable: SIGTERM exits with 0"

TUNDRA_PARENT_PID=$$ user_run +net_raw probe "$IF" "$NET.50"
expect_exit 0 "parent pid: the real parent lets the probe run"
TUNDRA_PARENT_PID=2 user_run +net_raw probe "$IF" "$NET.50"
expect_exit 143 "parent pid: another parent ends the probe with SIGTERM"
check "parent pid: nothing was probed" test ! -s "$OUT"
TUNDRA_PARENT_PID=junk user_run +net_raw probe "$IF" "$NET.50"
expect_exit 0 "parent pid: a malformed value is ignored"

PIDFILE=$WORK/pid

orphan_watch() {
	rm -f "$PIDFILE"
	sh -c "$1 ip netns exec $NS setpriv --reuid $TUID --regid $TGID \
		--clear-groups --inh-caps +net_raw $CAPBIN watch $IF addr $ADDR \
		>$OUT 2>$ERR & echo \$! >$PIDFILE; sleep 30" &
	wrapper=$!
	eventually "$2: watch running under a wrapper" 3 test -s "$PIDFILE"
	RUN_PID=$(cat "$PIDFILE")
	eventually "$2: watch locked down" 3 status_is Seccomp 2
	kill -KILL "$wrapper"
	wait "$wrapper" 2>/dev/null
}

orphan_watch "TUNDRA_PARENT_PID=\$\$" "parent death"
expect_out_in "^received Terminated, exiting$" 3 "parent death: watch gets SIGTERM"
eventually "parent death: watch is gone" 3 sh -c "! kill -0 $RUN_PID"
RUN_PID=

orphan_watch "" "no parent pid"
sleep 1
check "no parent pid: watch outlives its parent" running
kill -TERM "$RUN_PID"
eventually "no parent pid: watch stops on SIGTERM" 3 sh -c "! kill -0 $RUN_PID"
RUN_PID=

user_run -all probe "$IF" "$NET.50"
expect_exit 1 "no inheritable: probe exits with 1"
expect_err "^socket(AF_PACKET) error: Operation not permitted$" "no inheritable: probe cannot open the socket"
user_run -all watch "$IF" addr "$ADDR"
expect_exit 1 "no inheritable: watch exits with 1"
expect_err "^socket(AF_PACKET) error: Operation not permitted$" "no inheritable: watch cannot open the socket"
summary
