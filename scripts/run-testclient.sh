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

go run test-client.go -daemon '[fd00:f00d:cafe::7f00:54]:30255' -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]:31000' -remote 1-ff00:0:133,127.0.0.101:31001 -data "abc"