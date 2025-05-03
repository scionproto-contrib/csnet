WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export SCION_PATH="$WORKSPACE_DIR/network/scion"
export SCION_TESTNET_PATH="$WORKSPACE_DIR/network/scion-testnet"

cd "$SCION_TESTNET_PATH" || exit

go run test-server.go -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]:31000'