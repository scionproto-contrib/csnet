# Quick installation (for Linux / macOS)

To build the SCION library for use on Linux / macOS, simply run:
```
./install.sh
```

This script will download and build the dependencies of the SCION linrary:
- [Nghttp2](https://nghttp2.org/)
- [protobuf-c](https://github.com/protobuf-c/protobuf-c)


# Manual Installation (for Linux / macOS)
This section explains the steps which are done automatically by the `install.sh` script. This section is mainly meant to help understand the install steps for troubleshooting or custom installations.

## Installing dependencies

### Nghttp2

#### Required packages

```
sudo apt-get install g++ clang make binutils autoconf automake \
  autotools-dev libtool pkg-config \
  zlib1g-dev libssl-dev libxml2-dev libev-dev \
  libevent-dev libjansson-dev \
  libc-ares-dev libjemalloc-dev libsystemd-dev \
  ruby-dev bison libelf-dev
```

#### Building Nghttp2 (v.1.64.0)

Now change to the directory, where you would like to download the source files of Nghttp2.

```
wget https://github.com/nghttp2/nghttp2/releases/download/v1.64.0/nghttp2-1.64.0.tar.gz
tar xf nghttp2-1.64.0.tar.gz && rm nghttp2-1.64.0.tar.gz
cd nghttp2-1.64.0

./configure --enable-lib-only --prefix=/path/to/install/location
make
sudo make install
```
Notes:
- On Ubuntu 24.04, the library will be put into `/usr/local/lib`
- For more information on Nghttp2, see: https://github.com/nghttp2/nghttp2

</br>

### protobuf-c

#### Building protobuf-c (v.1.5.0)

Now change to the directory, where you would like to download the source files of protobuf-c.

```
wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.5.0/protobuf-c-1.5.0.tar.gz 
tar xf protobuf-c-1.5.0.tar.gz && rm protobuf-c-1.5.0.tar.gz
cd protobuf-c-1.5.0

./configure --disable-protoc --prefix=/path/to/install/location
make
sudo make install
```
Notes:
- On Ubuntu 24.04, the library will be put into `/lib`
- For more information on protobuf-c, see: https://github.com/protobuf-c/protobuf-c/wiki


</br>

---

## Building libscion
```
make
```