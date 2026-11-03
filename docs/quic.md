# QUIC over SCION (`scion_quic`)

SCION has no TCP. Applications that need a reliable, encrypted byte stream (MQTT, HTTP/3, file transfer, ...) use
QUIC over SCION UDP instead. `scion_quic` is an optional library on top of csnet that provides QUIC client connections
with one bidirectional stream, so that applications do not have to wire a QUIC implementation to csnet sockets
themselves. It plays the role of `DialQUIC` in the Go [pan](https://github.com/netsec-ethz/scion-apps/tree/master/pkg/pan)
library.

```
application (e.g. MQTT)
scion_quic        lib/quic: QUIC client, one bidirectional stream          scion/scion_quic.h
  ngtcp2          QUIC
  TLS backend     picotls + mbedTLS (default, also on the ESP32) or quictls
csnet             SCION UDP sockets                                         scion/scion.h
```

## Building

The library is not built by default:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_QUIC=ON -DBUILD_EXAMPLES=ON -B build-release
cmake --build build-release --target simple_quic_client
```

- `BUILD_QUIC`: build `scion_quic` (target `scion_quic`, links `scion`).
- `SCION_QUIC_TLS`: the TLS backend, `picotls` (default) or `quictls`.

The dependencies are fetched and built by CMake: ngtcp2 v1.12.0 (compiled from its sources, see
`cmake/Ngtcp2Sources.cmake`) and either picotls (pinned commit) with mbedTLS 4.1.0 or quictls 1.1.1w.

On the ESP32, enable `SCION QUIC` → `Build the QUIC library` in `idf.py menuconfig` (`CONFIG_CSNET_QUIC`), see
[esp32/README.md](../esp32/README.md). The component `esp32/components/scion_quic` uses the same sources with picotls
and ESP-IDF's mbedTLS, which uses the hardware AES, SHA and bignum accelerators of the ESP32.

## Usage

```c
#include <scion/scion_quic.h>

struct scion_quic_config config = {
	.alpn = "mqtt",                  // application protocol, required
	.server_name = "broker.example", // SNI, and the name the certificate must match
	.ca_pem = ca, .ca_pem_len = len, // trusted CAs (PEM); NULL: the server is NOT verified
};
struct scion_quic_conn *conn;
int ret = scion_quic_connect(&conn, network, (struct sockaddr *)&addr, addrlen, ia, &config);

scion_quic_write(conn, data, len); // queued until the handshake is done
for (;;) {
	if ((ret = scion_quic_wait(conn, 100)) != 0) break;  // or: poll scion_quic_getfd() with scion_quic_timeout(),
	ssize_t n = scion_quic_read(conn, buf, sizeof(buf)); //     then scion_quic_process()
	...                                                  // n > 0: data, 0: end of stream, SCION_ERR_WOULD_BLOCK
}
scion_quic_close(conn);
```

The library has no event loop of its own: `scion_quic_wait()` covers simple programs, and `scion_quic_getfd()`,
`scion_quic_timeout()` and `scion_quic_process()` integrate a connection into an existing loop (`poll`, libev,
FreeRTOS tasks). See `examples/simple_quic_client.c`, which runs on Linux and on the ESP32.

Design:

- One bidirectional stream per connection, opened by the client after the handshake (the mapping of MQTT over QUIC
  and similar protocols).
- QUIC packets are at most 1200 bytes, which fits any SCION path.
- Flow control windows of 64 KB (stream) and 128 KB (connection); received data is buffered until the application
  reads it, and the window is only extended then (back-pressure).
- The underlying SCION socket is connected; an optional path policy (`config.policy`) and local address
  (`config.local_addr`, e.g. the Wi-Fi address of an ESP32) can be set.

Not yet: a server side (listener), several streams, connection migration on path changes, client certificates.

## TLS backends

| | picotls + mbedTLS | quictls |
|---|---|---|
| License | MIT + Apache-2.0 | Apache-2.0 (OpenSSL 1.1.1 fork) |
| ESP32 | yes, mbedTLS of ESP-IDF with hardware crypto | no (too large) |
| Server verification | `lib/quic/tls_picotls.c`: chain and name with `mbedtls_x509_crt_verify()`, CertificateVerify with `mbedtls_pk_verify_ext()` (ECDSA P-256/P-384, RSA-PSS) | OpenSSL |
| Status | maintained | based on OpenSSL 1.1.1, which is end of life since 2023 (ngtcp2 also supports the QUIC API of OpenSSL >= 3.5, backend `ossl`) |

Three small adaptations make picotls work with mbedTLS 4 and ngtcp2, all in `lib/quic`:

- `compat/picotls/openssl.h`: ngtcp2's picotls crypto backend is written for picotls' OpenSSL binding; this header maps
  its symbols to the mbedTLS binding.
- `compat/mbedtls4`: mbedTLS 4 moved `mbedtls/chacha20.h` (private now) and removed `mbedtls/ecdh.h`, which
  picotls' mbedTLS binding includes.
- `patches/picotls-mbedtls-aead-output-size.patch`: picotls passes `SIZE_MAX` as AEAD output size, which fails with
  mbedTLS >= 3.6 (`PSA_ERROR_INSUFFICIENT_MEMORY`, PSA copies the caller's buffers). To be sent upstream.

Testing: `scripts/run-quic-server.sh` (helloquic of scion-apps), then `./simple_quic_client -t <topology.json>` in
AS 1-ff00:0:133; `-c ca.pem -s name` to verify the server, `-d` for a packet log.
