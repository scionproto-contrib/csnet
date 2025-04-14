if [ -z $SCION_TESTNET_PATH ]
then
  echo "SCION_TESTNET_PATH not set"
  exit 1
fi

if [ -z SCION_PATH ]
then
  echo "SCION_PATH not set"
  exit 1
fi

cd $SCION_TESTNET_PATH

go run test-server.go -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]:31000'