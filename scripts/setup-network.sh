#!/bin/bash

# ensure go is installed
if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go is not installed. Install go and try again!" >&2
  exit 1
fi

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$WORKSPACE_DIR/network"

export SCION_PATH="$WORKSPACE_DIR/network/scion"
export SCION_TESTNET_PATH="$WORKSPACE_DIR/network/scion-testnet"
export SCION_APPS_PATH="$WORKSPACE_DIR/network/scion-apps"

echo "Installing SCION..."
git clone https://github.com/scionproto/scion.git "$SCION_PATH"
cd "$SCION_PATH" || exit
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./router/cmd/router

echo "Installing SCION Test Network..."
git clone https://github.com/marcfrei/scion-testnet.git "$SCION_TESTNET_PATH"
cd "$SCION_TESTNET_PATH" || exit
go build scion-testnet.go
go build test-server.go
go build test-client.go

echo "Installing SCION Apps..."
git clone https://github.com/netsec-ethz/scion-apps.git "$SCION_APPS_PATH"

echo "Installation completed"