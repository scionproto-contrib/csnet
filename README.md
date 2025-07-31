# csnet

csnet is a C application programming library for communicating over a SCION network. More information about SCION can be
found [here](https://docs.scion.org/en/latest/overview.html). csnet exposes
a [BSD-socket-like](https://en.wikipedia.org/wiki/Berkeley_sockets) API to send and receive
SCION packets. csnet provides similar functionalities
to [snet (Go)](https://pkg.go.dev/github.com/scionproto/scion/pkg/snet), [PAN (Go)](https://pkg.go.dev/github.com/netsec-ethz/scion-apps/pkg/pan), [JPAN (Java)](https://github.com/scionproto-contrib/jpan)
and
[scion-rs (Rust)](https://github.com/MystenLabs/scion-rs).

### Feature Summary:

- Linux, MacOS and ESP32 support
- UDP over SCION
- SCMP (ICMP for SCION)
- Explicit SCION path selection
- Path selection policies
- Automatic DNS-based end-host bootstrapping
- SCION ping tool

To get started with csnet follow the building and installation instructions below and afterward continue with
the [Getting Started Guide](./docs/getting-started.md).

## Requirements

Building and installing the library and examples requires CMake 3.22 or newer
(download [here](https://cmake.org/download/)).

All the requirements for building the library and examples are fetched automatically with CMake and installed in the
workspace build directory, ensuring the rest of the system remains unaffected.

Running the examples (in `./examples`) additionally requires the following:

- a running local SCION Network (see [Local SCION Network Setup](#local-scion-network-setup) for setup instructions)
- some examples have additional requirements, consult the [README](./examples/README.md) for more information

Building the documentation (in `./docs`) requires:

- doxygen (download [here](https://www.doxygen.nl/download.html))
- graphviz (download [here](https://graphviz.org/download/))

## Building and Installation

Set up the CMake build directory in `./build-release` with

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_LIB=ON -DBUILD_CMD=ON -DBUILD_EXAMPLES=ON -DBUILD_TESTS=OFF -DBUILD_DOCS=OFF -B build-release
```

The following options exist:

- `BUILD_LIB`: build the library in `./lib`
- `BUILD_CMD`: build the command line tools in `./cmd`
- `BUILD_EXAMPLES`: build the examples in `./examples`.
- `BUILD_TESTS`: build the tests in `./tests`. May also build the command line tools in `./cmd` that are required by the
  tests even if `DBUILD_CMD` is `OFF`.
- `BUILD_DOCS`: build the docs which are output to `./docs/api`.

Build everything with

```bash
cmake --build build-release
```

To install the library execute:

```bash
 cmake --install build-release --prefix "your installation directory"
```

Depending on the installation directory you might need to run the command with `sudo`.

The installation will produce the static libraries `lib/libscion.a`, `lib/libnghttp2.a`, `lib/libz.a`,
`lib/libprotobuf.a`,
`lib/libcurl.a`, the header file `include/scion/scion.h`, and the command-line tool `bin/ping` in your installation
directory. When using the library make sure to link against all the static libraries produced by the installation.

## Local SCION Network Setup

Requirements:

- Linux, MacOS or WSL
- Go 1.23 or newer (download [here](https://go.dev/dl/))

To set up a local SCION Network execute the setup script in `scripts/setup-network.sh`. After successfully installing
it, the network can be started with `sudo scripts/run-testnet.sh`. Press `Ctrl+C` to shut down the test network.

## ESP32

EPS32 specific instructions can be found [here](./esp32/README.md).

## Library Development

### Requirements

Required tools:

- `protobuf` and `protobuf-c`: Protobuf to C compiler required to generate code from .proto files to talk to a control
  server.
- (optionally) `clang-format`: Code formatter we use.

### Building in Debug Mode

To build the library in debug mode set up a CMake build directory with

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_LIB=ON -DBUILD_CMD=ON -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON -DBUILD_DOCS=ON -B build-debug
```

and then to build everything run

```bash
cmake --build build-debug
```

You can also build a specific target with the following command

```bash
cmake --build cmake-build-debug --target TARGET
```

where `TARGET` is a valid CMake target defined in the project. Examples are:

- `doxygen` for the documentation
- `scion` for the library
- `ping` for the ping command line tool
- `udp_example` for the `udp.c` example
- `server_example` for the `server.c` example
- etc.

### Running the Tests Locally

Before running the tests locally, ensure the following requirements are met:

1. The local SCION network has been installed as explained [here](#local-scion-network-setup).
2. You have built all targets.
3. There is **no** local SCION network running at the moment.

To execute all the tests run:

```bash
sudo ctest --extra-verbose --output-on-failure --test-dir build-debug
```

To execute only the unit tests run:

```bash
sudo ctest --extra-verbose --output-on-failure -L unit --test-dir build-debug
```

To execute only the e2e tests run:

```bash
sudo ctest --extra-verbose --output-on-failure -L e2e --test-dir build-debug
```

> **Info**: The local SCION network will automatically start before the end-to-end tests run and shut down after they
> complete.

### Releasing a New Version

A new release of the library can be created [here](https://github.com/scionproto-contrib/csnet/releases/new).

### Code Quality

To automatically format the code install `clang-format` and run

```
find . -iname "*.h" -o -iname "*.c"  | xargs clang-format -i
```

Entire files and directories are ignored by adding them to `.clang-format-ignore`
