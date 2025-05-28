#!/bin/bash

WORKSPACE_DIR=@CMAKE_SOURCE_DIR@

NETWORK_STARTUP_TIME=${NETWORK_STARTUP_TIME:-10}
TEST_SERVER_STARTUP_TIME=${TEST_SERVER_STARTUP_TIME:-20}

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

./scion-testnet cryptogen topos/default
nohup ./scion-testnet run topos/default > scion-testnet.log 2>&1 < /dev/null &
echo $! > scion-testnet.pid
sleep "$NETWORK_STARTUP_TIME"

nohup ./test-server -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]:31000' > test-server.log 2>&1 < /dev/null &
echo $! > test-server.pid
sleep "$TEST_SERVER_STARTUP_TIME"

echo "Started network and hosts"