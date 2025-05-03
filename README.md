# CSNET

**Attention**: This repository is still under construction! 🛠️🚧

## Requirements

Building and installing the library and examples requires CMake 3.22 or newer (
download [here](https://cmake.org/download/)).

All the requirements for building the library and examples are fetched automatically with CMake.

Running the examples (in `./examples`) additionally requires the following:

- a running local SCION Network (see [Local SCION Network Setup](#local-scion-network-setup) for setup instructions)
- some examples have additional requirements, consult the [README](./examples/README.md) for more information

Building the documentation (in `./docs`) requires:

- doxygen (download [here](https://www.doxygen.nl/download.html))
- graphviz (download [here](https://graphviz.org/download/))

## Building and Installation

Setup the CMake build directory in `./dist` with

```bash
cmake -DBUILD_EXAMPLES=ON -DBUILD_TESTS=OFF -DBUILD_DOCS=OFF -B dist
```

The following options exist:

- `BUILD_EXAMPLES`: additionally build the examples in `./examples`.
- `BUILD_TESTS`: additionally build the tests in `./tests` and some of the examples in `./examples` that serve as E2E
  tests. This means that even if `BUILD_EXAMPLES` is `OFF` some examples may still be built if `BUILD_TESTS` is `ON`.
- `BUILD_DOCS`: additionally build the docs which are output to `./docs`.

Build everything with

```bash
cmake --build dist
```

To install the library execute:

```bash
 cmake --install dist --prefix "your installation directory"
```

This will produce the static libraries `lib/libscion.a`, `lib/libnghttp2.a`, `lib/libprotobuf.a` and the header
file `include/scion/scion.h` in your installation directory. When using the library make sure to link against all the
libraries produced by the installation.

## Local SCION Network Setup

Requirements:

- Linux, MacOS or WSL
- Go 1.23 or newer (download [here](https://go.dev/dl/))

To set up a local SCION Network execute the setup script in `scripts/setup-network.sh`. After successfully installing
it, the network can be started with `scripts/run-testnet.sh`.

## ESP32

EPS32 specific instructions can be found [here](./esp32/README.md).

## Library Development

### Requirements

Required tools:

- `protobuf` and `protobuf-c`: Protobuf to C compiler required to generate code from .proto files to talk to a control
  server.
- (optionally) `clang-format`: Code formatter we use.

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
