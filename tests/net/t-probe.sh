. "$(dirname "$0")/lib.sh"

setup
EV=$(evil_mac)

probe "$NET.50"
expect_exit 0 "free: nobody answers"
expect_out "^free$" "free: reported"

in_evil ip addr add "$NET.60/24" dev "$EVIF"
probe "$NET.60"
expect_exit 0 "taken: the address is in use"
expect_out "^taken mac $EV src $EV$" "taken: the owner is reported"
check "taken: a single conflict raises no alert" test ! -s "$ERR"
check "taken: the history is written" test -s "$HISTORY/$IF"

reset_history
in_evil ip addr add "$NET.61/24" dev "$EVIF"
in_evil ip addr add "$NET.62/24" dev "$EVIF"
probe "$NET.60"
probe "$NET.61"
probe "$NET.62"
expect_exit 111 "A: a third address taken by the same host"
expect_err "^alert 111/4 stop by tundra-blueice-arp on $IF ts [0-9]*\.[0-9]\{3\} reply force,disconnect info case A claim " "A: the alert line"
check "A: no result on stdout after a stop" test ! -s "$OUT"
probe "$NET.60" accept A/4
expect_exit 0 "A accepted: the probe completes"
expect_err "^alert 111/4 warn .* reply ack,disconnect " "A accepted: the alert becomes a warning"
expect_out "^taken mac $EV" "A accepted: the conflict is still reported"

reset_history
start_helper "$TOOLS/arpresp" "$EVIF"
sleep 0.2
n=0
RUN_EXIT=0
while [ "$n" -lt 10 ] && [ "$RUN_EXIT" -eq 0 ]; do
	n=$((n + 1))
	probe "$NET.$((100 + n))"
done
expect_exit 111 "B: many hosts claiming addresses"
expect_err " info case B " "B: the alert names the case"
check "B: raised on the tenth responder" [ "$n" -eq 10 ]
stop_helper
check "B: the responder is gone" sh -c "[ -z \"\$(ip netns pids $EVIL)\" ]"

reset_history
run_bg probe "$IF" "$NET.70"
sleep 0.3
claim 01:00:5e:00:00:01 "$NET.70" "$NET.70" 02:cc:cc:cc:cc:cc
wait_run
expect_exit 111 "mac-addr: a crafted MAC answers at once"
expect_err "^alert 111/7 stop .* info case mac-addr ip $NET.70 claim $NET.70@01:00:5e:00:00:01 src 02:cc:cc:cc:cc:cc forged 1 " "mac-addr: the alert line"

reset_history
run_bg probe "$IF" "$NET.71"
sleep 0.3
claim 02:aa:aa:aa:aa:01 "$NET.71" "$NET.71" 02:dd:dd:dd:dd:dd
wait_run
expect_exit 0 "forged: a single conflict"
expect_out "^taken mac 02:aa:aa:aa:aa:01 src 02:dd:dd:dd:dd:dd$" "forged: sender and frame source reported"

run probe nosuch0 "$NET.5"
expect_exit 1 "a missing interface exits with 1"
run probe "$IF" 999.0.0.1
expect_exit 2 "an invalid address exits with 2"
run probe "$IF" "$NET.5" accept Z/3
expect_exit 2 "an invalid accept exits with 2"
run probe "$IF" "$NET.5" accept A/4 accept B/4
expect_exit 2 "a repeated option exits with 2"
run probe "$IF"
expect_exit 2 "a missing address exits with 2"
run --version
expect_exit 0 "--version exits with 0"
expect_out "^tundra-blueice-arp " "--version prints the version"
summary
