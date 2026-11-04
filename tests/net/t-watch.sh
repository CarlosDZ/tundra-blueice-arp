. "$(dirname "$0")/lib.sh"

setup
GWMAC=$(cat "/sys/class/net/$BR/address")
EVMAC=02:aa:aa:aa:aa:01

start_watch gw "$NET.1"
expect_out_in "^gateway is at $GWMAC$" 5 "learns the gateway MAC"
claim "$EVMAC" "$ADDR" "$ADDR"
expect_out_in "^defending address $ADDR against $EVMAC$" 3 "a single claim is defended"
claim "$EVMAC" "$ADDR" "$ADDR"
wait_exit 5
expect_exit 1 "once: a second claim within the interval gives up"
expect_out "^conflict addr $ADDR mac $EVMAC$" "once: the conflict is reported"
check "once: a plain conflict raises no alert" test ! -s "$ERR"
check "claims are kept in the history" grep -q "bound 1" "$HISTORY/$IF"

reset_history
start_watch gw "$NET.1"
expect_out_in "gateway is at" 5 "C: watching"
claim 02:aa:aa:aa:aa:01 "$ADDR" "$ADDR"
sleep 3
claim 02:aa:aa:aa:aa:02 "$ADDR" "$ADDR"
sleep 3
claim 02:aa:aa:aa:aa:03 "$ADDR" "$ADDR"
wait_exit 5
expect_exit 111 "C: repeated claims stop"
expect_err "^alert 111/6 stop by tundra-blueice-arp on $IF .* info case C ip $ADDR claim " "C: the alert line"

reset_history
start_watch gw "$NET.1" accept C/6
expect_out_in "gateway is at" 5 "C accepted: watching"
claim 02:aa:aa:aa:aa:01 "$ADDR" "$ADDR"
sleep 3
claim 02:aa:aa:aa:aa:02 "$ADDR" "$ADDR"
sleep 3
claim 02:aa:aa:aa:aa:03 "$ADDR" "$ADDR"
expect_out_in "^defending address $ADDR against 02:aa:aa:aa:aa:03$" 3 "C accepted: the address is still defended"
expect_err "^alert 111/6 warn .* reply ack,disconnect info case C " "C accepted: the alert becomes a warning"
sleep 3
claim 02:aa:aa:aa:aa:03 "$ADDR" "$ADDR"
sleep 0.5
check "C accepted: the same case and MAC warns once" err_lines " case C " 1
check "C accepted: still running" running
stop_watch
expect_exit 0 "SIGTERM exits with 0"
expect_out "^received " "SIGTERM is reported"

reset_history
start_watch gw "$NET.1" defend always
expect_out_in "gateway is at" 5 "always: watching"
claim 02:aa:aa:aa:aa:01 "$ADDR" "$ADDR"
sleep 0.3
claim 02:aa:aa:aa:aa:02 "$ADDR" "$ADDR"
expect_out_in "^address $ADDR claimed by 02:aa:aa:aa:aa:02, holding it$" 3 "always: a claim within the interval is held"
check "always: never gives up" running
claim 01:00:5e:00:00:01 "$ADDR" "$ADDR" 02:cc:cc:cc:cc:cc
wait_exit 5
expect_exit 111 "always: a crafted MAC still stops"
expect_err " info case mac-addr ip $ADDR claim $ADDR@01:00:5e:00:00:01 src 02:cc:cc:cc:cc:cc forged 1 " "always: mac-addr alert line"

reset_history
start_watch gw "$NET.1"
expect_out_in "gateway is at" 5 "D: watching"
claim 02:bb:bb:bb:bb:bb "$NET.1" "$ADDR"
wait_exit 5
expect_exit 111 "D: another MAC for the gateway stops"
expect_err "^alert 111/8 stop .* info case D gw $NET.1 known $GWMAC seen $GWMAC,02:bb:bb:bb:bb:bb forged 0 " "D: the alert line"

start_watch gw "$NET.1" accept D/8
expect_out_in "gateway is at" 5 "D accepted: watching"
claim 02:bb:bb:bb:bb:bb "$NET.1" "$ADDR"
sleep 0.5
expect_err "^alert 111/8 warn .* info case D " "D accepted: the alert becomes a warning"
check "D accepted: still running" running
stop_watch

start_watch gw "$NET.1"
expect_out_in "gateway is at" 5 "mac-gw: watching"
claim 01:00:5e:00:00:01 "$NET.1" "$ADDR" 02:cc:cc:cc:cc:cc
wait_exit 5
expect_exit 111 "mac-gw: a crafted MAC for the gateway stops"
expect_err "^alert 111/8 stop .* info case mac-gw gw $NET.1 known $GWMAC seen 01:00:5e:00:00:01 src 02:cc:cc:cc:cc:cc forged 1 " "mac-gw: the alert line"

start_watch gw "$NET.2"
sleep 0.2
claim 01:00:5e:00:00:01 "$NET.2" "$ADDR"
wait_exit 5
expect_exit 111 "mac-gw: a crafted only reply while learning stops"
check "mac-gw: the crafted MAC is not learned" sh -c "! grep -q 'gateway is at' '$OUT'"

start_watch gw "$NET.1"
expect_out_in "gateway is at" 5 "mac-net: watching"
claim 01:00:5e:00:00:01 "$NET.99" "$NET.99" 02:cc:cc:cc:cc:cc
sleep 0.3
claim 01:00:5e:00:00:01 "$NET.99" "$NET.99" 02:cc:cc:cc:cc:cc
sleep 0.5
expect_err "^alert 111/2 warn .* info case mac-net ip $NET.99 sha 01:00:5e:00:00:01 src 02:cc:cc:cc:cc:cc forged 1 " "mac-net: the alert line"
check "mac-net: warns once" err_lines " case mac-net " 1
check "mac-net: still running" running
stop_watch

reset_history
start_watch
sleep 1.5
check "without gw no gateway is learned" sh -c "! grep -q 'gateway is at' '$OUT'"
in_ns ip link set "$IF" down
sleep 1.5
check "carrier loss keeps the sensor running" running
in_ns ip link set "$IF" up
sleep 1
claim "$EVMAC" "$ADDR" "$ADDR"
expect_out_in "^defending address $ADDR against $EVMAC$" 3 "carrier back: defended again"
in_ns ip link del "$IF"
wait_exit 5
expect_exit 1 "a removed interface exits with 1"
expect_err "^interface $IF removed$" "the removal is reported"

run watch "$IF"
expect_exit 2 "watch without addr exits with 2"
run watch "$IF" addr "$ADDR" defend sometimes
expect_exit 2 "an invalid defend exits with 2"
summary
