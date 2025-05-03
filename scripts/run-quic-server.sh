WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export SCION_QUIC_SERVER_PATH="$WORKSPACE_DIR/network/scion-apps/_examples/helloquic"

cd "$SCION_QUIC_SERVER_PATH" || exit

SCION_DAEMON_ADDRESS="[fd00:f00d:cafe::7f00:54]:30255" go run helloquic.go -listen '[fd00:f00d:cafe::7f00:55]:31003'