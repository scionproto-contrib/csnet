# Running the Example on ESP32

## Requirements

To connect the ESP32 to the SCION network running locally on your machine, follow these steps:

1. Ensure the ESP32 and your machine are connected to the same network (e.g., phone hotspot, ETH network, etc.)
2. Determine your machine’s local IP address on the shared network (e.g., by using `ifconfig` on Linux or `ipconfig` on
   Windows).
3. In the file `network/scion-testnet/topos/default/ASff00_0_133/topology.json`, replace all IP addresses in the `addr`
   and `internal_addr` fields with the IP address of your machine.
4. Copy the modified topology file to:
    - `topology/topology.json`
    - `esp32/spiffs_partition/topology.json`.
5. If you are using WSL, you need to
   enable [mirrored mode networking](https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking),
   otherwise your ESP32 won't be able to connect to the local SCION network running in WSL.
6. Ensure your machine’s firewall allows:
    - Incoming UDP traffic on the border router ports (e.g., 31068 and 31070)
    - Incoming TCP traffic on the control service ports (e.g., 31066)

      (Note: If you are using WSL, adjust the inbound firewall rules in the Windows Defender Firewall).
7. Start the local SCION network:
   ```bash
   sudo ./scripts/run-testnet.sh
   ```
8. Start a local SCION UDP server:
   ```bash
   ./scripts/run-testserver.sh
   ```
9. Make sure
   the [ESP-IDF toolchain](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html)
   is installed.

## Running the Example

To run the example program located in `./main/main.c`:

1. Set the target:
   ```bash
   idf.py set-target esp32s3
   ```
   Ensure the necessary environment variables are set (see Step 4 of the ESP-IDF installation guide).
2. (optional) To avoid entering your Wi-Fi credentials every time:
    - Run `idf.py menuconfig`
    - Navigate to `Example Connection Configuration`
    - Uncheck `Get ssid and password from stdin`
    - Check `Provide wifi connect commands`
    - Enter your Wi-Fi SSID and password
3. Build the project:
   ```bash
   idf.py build
   ```
4. Connect the ESP32-S3 board to your machine via UART. Determine the port it is connected to.

   Refer
   to: [Establish Serial Connection with ESP32](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/establish-serial-connection.html)

   If using WSL, USB devices must be bound and attached from Windows
   first: [WSL - Connect USB devices](https://learn.microsoft.com/en-us/windows/wsl/connect-usb#attach-a-usb-device)
5. Run:
   ```bash
   idf.py -p <PORT> -b 460800 flash
   ```
6. Run:
   ```bash
   idf.py -p <PORT> -b 115200 monitor
   ```
   To exit, hit `Ctrl + T` and then `Ctrl + X`.