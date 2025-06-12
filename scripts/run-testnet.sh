#!/bin/bash

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export SCION_PATH="$WORKSPACE_DIR/network/scion"
export SCION_TESTNET_PATH="$WORKSPACE_DIR/network/scion-testnet"

cd "$SCION_TESTNET_PATH" || exit

rm -rf logs gen-cache
mkdir logs gen-cache

./scion-testnet ifconfig topos/default

./scion-testnet cryptogen topos/default
./scion-testnet run topos/default

./scion-testnet ifconfig -c topos/default