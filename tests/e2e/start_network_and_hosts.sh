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

# The paths between all hosts are available when every core AS has received the core segments of all other core ASes
# and every other AS has registered its up and down segments.
network_is_ready() {
  local core_ias non_core_ias ia log num_core
  core_ias=$(awk '/^Core:/ {f=1; next} /^Non-core:/ {f=0} f && /^- / {print $2}' topos/default/as_list.yml)
  non_core_ias=$(awk '/^Non-core:/ {f=1; next} f && /^- / {print $2}' topos/default/as_list.yml)
  num_core=$(echo "$core_ias" | wc -l)

  for ia in $core_ias; do
    log=$(ls logs/cs"${ia//:/_}"-*.log 2> /dev/null | head -n 1)
    [ -n "$log" ] &&
      grep -q "\"seg_type\": \"core\", \"count\": [1-9][0-9]*, \"start_isd_ases\": $((num_core - 1))" "$log" || return 1
  done
  for ia in $non_core_ias; do
    log=$(ls logs/cs"${ia//:/_}"-*.log 2> /dev/null | head -n 1)
    [ -n "$log" ] && grep -q "\"seg_type\": \"up\", \"count\": [1-9]" "$log" &&
      grep -q "\"seg_type\": \"down\", \"count\": [1-9]" "$log" || return 1
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
