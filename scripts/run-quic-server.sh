if [ -z $SCION_QUIC_SERVER_PATH ]
then
  echo "SCION_QUIC_SERVER_PATH not set"
  exit 1
fi

cd $SCION_QUIC_SERVER_PATH

SCION_DAEMON_ADDRESS=[fd00:f00d:cafe::7f00:54]:30255 go run helloquic.go -listen '[fd00:f00d:cafe::7f00:55]:31000'