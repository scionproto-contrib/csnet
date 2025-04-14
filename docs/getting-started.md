# Getting started

## Installation
If you want to run the Linux/macOS examples, follow the installation steps [here](/docs/installation_unix.md).

If you want to run the ESP32 examples, you only need to install the `ESP-IDF` (ESP IoT Development Framework), the official toolchain to program ESP chips. Installation guidelines: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html

## Setting up a SCION test network

To run a local test setup use the SCION testnet (https://github.com/marcfrei/scion-testnet).

After installation, open `topos/default/ASff00_0_222/topology.json` and replace all occurences of `127.0.0.209`, `127.0.0.210` and `127.0.0.211` with your local IP address (as seen within your current network). Copy the new version of the `topos/default/ASff00_0_222/topology.json` into this project under `spiffs_partition/topology.json`.

After starting the test network, create a server as described (i.e. `go run test-server.go -local 1-ff00:0:133,127.0.0.148:31000`). 

## Linux / macOS Examples

Navigate to the `examples/unix` directory. 
Select an example and change the source IP (currently `<Your IP Address here>`) to your local IP.
You can compile the examples located in this folder using the following command:
```
gcc -Wall -g -o main.out unix_XXX_example_main.c -I../../components ../../lib/libscion.a ../../lib/libprotobuf-c.a ../../lib/libnghttp2.a
```

Make sure the path to the topology.json in the given example is correct. The predefined pathes are designed to run the compiled program from the `examples/unix` directory.

## ESP32 Examples

Do the following steps to run the ESP32 client:

1. Copy a example from `examples/esp32/` into `/main` and rename the file to `main.c`
1. Run `idf.py set-target esp32s3` (make sure that the environment variables are set, see Step 4 of the ESP-IDF installation)
1. **IMPORTANT:** Run `idf.py menuconfig` and under `Partition Table > Partition Table` select `Custom partition table CSV` and under `Example Connection Configuration` set the SSID and password of your WiFi network.
1. Run `idf.py build`
1. Connect the esp32-S3 board to your machine, on the dev board, connect to UART. Find the port on which the devboard is connected. (https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/establish-serial-connection.html)
1. Run `idf.py -p <Port on which the ESP32 is connected> -b 460800 flash`
1. Run `idf.py -p <Port on which the ESP32 is connected> -b 115200 monitor`. To exit, hit `Ctrl + T` and then `Ctrl + X`.