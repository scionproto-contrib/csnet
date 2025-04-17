# CSNET

## Requirements

All the requirements for building the library (in `./lib`) are fetched automatically with CMake.

Building and running the examples (in `./examples`) additionally requires the following:

- a running local SCION Network (see [SCION Test Network Setup](#scion-testnetwork-setup))
- create a `topology.json` from the `topology.example.json` by filling in the respective IP addresses
- an installation of the QUIC-enabled Openssl
  fork (https://github.com/quictls/openssl/tree/OpenSSL_1_1_1w+quic)

## SCION Test Network Setup

To run a local test setup of the default topology use the SCION testnet (https://github.com/marcfrei/scion-testnet).
After successfully installing the testnet the network can be started with `scripts/run-testnet.sh`.
Some tests also require a running server which can be started with `scripts/run-testserver.sh`.

### Windows prerequisites

Currently, SCION is not supported on Windows, hence using WSL is recommended.

In order for your SCION test network to be accessible from your LAN the mirrored mode networking must be enabled in
WSL (see here for more information about mirrored mode networking).
Additionally, you must adjust the settings of your Windows Defender Firewall, because Windows blocks all incoming
connections by default.
Make sure to allow incoming connections with TCP on the port of the control service (for AS `1-ff00:0:133` this is
`31066`) and allow all incoming UDP connections on the ports of the border routers (for AS `1-ff00:0:133` this is
`31068` and `31070`).

## Building

Setup the CMake build with

```bash
cmake -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON -DBUILD_DOCS=ON -DOPENSSL_DIR="openssl dir" -B dist
```

The options `DBUILD_EXAMPLES`, `DBUILD_TESTS` and `DBUILD_DOCS` can also be turned off. Option `DOPENSSL_DIR` is only
required when building the examples. Make sure that `DOPENSSL_DIR` contains `lib/libssl.so` and `lib/libcrypto.so`.

Build everything with

```bash
cmake --build dist
```

The resulting binaries will be put in `./dist`.

## ESP32

EPS32 specific instructions can be found [here](./esp32/README.md).

## Development

### Requirements

Required tools:

- `protobuf` and `protobuf-c`: Protobuf to C compiler required to generate code from .proto files to talk to a control
  server.
- `ESP-IDF`: The ESP IoT Development Framework, official toolchain to program ESP chips. Installation
  guidelines: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html
- (optionally) `clang-format`: Code formatter we use.
- (optionally) `doxygen` and `graphviz`: Tools for generating API docs.

Windows (WSL):

- USBIPD-WIN: software for sharing locally connected USB devices with WSL,
  see: https://learn.microsoft.com/en-us/windows/wsl/connect-usb

### Code Quality

To automatically format the code install `clang-format` (e.g., via Homebrew) and run

```
find . -iname "*.h" -o -iname "*.c"  | xargs clang-format -i
```

Individual sections can be excluded from formatting like follows:

```
// clang-format off
...
// clang-format on
```

Entire files and directories are ignored by adding them to `.clang-format-ignore`
