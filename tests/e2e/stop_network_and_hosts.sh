#!/bin/bash

WORKSPACE_DIR=@CMAKE_SOURCE_DIR@

export SCION_PATH="$WORKSPACE_DIR/network/scion"
export SCION_TESTNET_PATH="$WORKSPACE_DIR/network/scion-testnet"

cd "$SCION_TESTNET_PATH" || exit

kill -TERM "$(cat test-server.pid)"
kill -INT "$(cat scion-testnet.pid)"

./scion-testnet ifconfig -c topos/default

exit 0