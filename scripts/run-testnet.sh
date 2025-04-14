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

rm -rf logs gen-cache
mkdir logs gen-cache

sudo ./scion-testnet ifconfig topos/default

./scion-testnet cryptogen topos/default
./scion-testnet run topos/default

sudo ./scion-testnet ifconfig -c topos/default