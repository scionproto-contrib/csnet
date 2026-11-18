#!/bin/bash

WORKSPACE_DIR=@CMAKE_SOURCE_DIR@

# The longest time in seconds to wait for the network and for the test server. The script continues as soon as they
# are ready.
STARTUP_TIMEOUT=${STARTUP_TIMEOUT:-60}
TEST_SERVER_IA=2-ff00:0:222
TEST_SERVER_ADDR=fd00:f00d:cafe::7f00:55
TEST_SERVER_PORT=31000

export SCION_PATH="$WORKSPACE_DIR/network/scion"
export SCION_TESTNET_PATH="$WORKSPACE_DIR/network/scion-testnet"

cd "$SCION_TESTNET_PATH" || exit

if pgrep -x scion-testnet > /dev/null; then
  echo "Detected running testnet. Stop the running testnet first and try again."
  exit 1
fi

if pgrep -x test-server > /dev/null; then
  echo "Detected running test server. Stop the running test server first and try again."
  exit 1
fi

rm -rf logs gen-cache
mkdir logs gen-cache

./scion-testnet ifconfig topos/default

# Waits until the condition (a command) holds, for at most the given number of seconds.
wait_for() {
  local timeout=$1
  shift
  local waited=0
  while ! "$@"; do
    if [ "$waited" -ge "$((timeout * 10))" ]; then
      echo "Timeout after $timeout s: $*"
      return 1
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
}

# Checks that the control service registered as many segments of the type in its last two beaconing rounds, and more
# than none.
segments_are_stable() {
  local log=$1 seg_type=$2 counts
  mapfile -t counts < <(grep "Registered beacons" "$log" | grep "\"seg_type\": \"$seg_type\"" | tail -n 2 |
    grep -o '"count": [0-9]*' | cut -d' ' -f2)
  [ "${#counts[@]}" -eq 2 ] && [ "${counts[0]}" -eq "${counts[1]}" ] && [ "${counts[0]}" -gt 0 ]
}

# The paths between all hosts are available when beaconing has converged. A beacon travels one hop per beaconing
# round, so when no control service registered a new segment in a round, no beacon is on its way any more. The core
# ASes register core segments, the other ASes up and down segments.
network_is_ready() {
  local core_ias non_core_ias ia log
  core_ias=$(awk '/^Core:/ {f=1; next} /^Non-core:/ {f=0} f && /^- / {print $2}' topos/default/as_list.yml)
  non_core_ias=$(awk '/^Non-core:/ {f=1; next} f && /^- / {print $2}' topos/default/as_list.yml)

  for ia in $core_ias; do
    log=$(ls logs/cs"${ia//:/_}"-*.log 2> /dev/null | head -n 1)
    [ -n "$log" ] && segments_are_stable "$log" core || return 1
  done
  for ia in $non_core_ias; do
    log=$(ls logs/cs"${ia//:/_}"-*.log 2> /dev/null | head -n 1)
    [ -n "$log" ] && segments_are_stable "$log" up && segments_are_stable "$log" down || return 1
  done
}

test_server_is_ready() {
  [ -n "$(ss -H -lun "src [$TEST_SERVER_ADDR]:$TEST_SERVER_PORT")" ]
}

./scion-testnet cryptogen topos/default
nohup ./scion-testnet run topos/default > scion-testnet.log 2>&1 < /dev/null &
echo $! > scion-testnet.pid
wait_for "$STARTUP_TIMEOUT" network_is_ready

nohup ./test-server -local "$TEST_SERVER_IA,[$TEST_SERVER_ADDR]:$TEST_SERVER_PORT" > test-server.log 2>&1 < /dev/null &
echo $! > test-server.pid
wait_for "$STARTUP_TIMEOUT" test_server_is_ready

echo "Started network and hosts"
