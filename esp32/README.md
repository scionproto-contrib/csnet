# Running the client on ESP32

Do the following steps to run the ESP32 client:

1. Copy the topology.json of the local AS ("in which" the ESP32 runs) into `spiffs_partition` and adapt the destination
   IP and IA in `main/main.c`, depending on the AS you use to run the server (See SCION Test Setup).
2. Run `idf.py set-target esp32s3` (make sure that the environment variables are set, see Step 4 of the ESP-IDF
   installation)
3. **IMPORTANT:** Run `idf.py menuconfig` and under `Partition Table > Partition Table` select
   `Custom partition table CSV` and under `Example Connection Configuration` set the SSID and password of your WiFi
   network. Under `Serial flasher config` set the `Flash size` to `4MB`.
4. Run `idf.py build`
5. Connect the esp32-S3 board to your machine, on the dev board, connect to UART. Find the port on which the devboard is
   connected. (https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/establish-serial-connection.html)
   When using WSL you have to bind and attach the USB devices in Windows first (
   see https://learn.microsoft.com/en-us/windows/wsl/connect-usb#attach-a-usb-device).
6. Run `idf.py -p <Port on which the ESP32 is connected> -b 460800 flash`
7. Run `idf.py -p <Port on which the ESP32 is connected> -b 115200 monitor`. To exit, hit `Ctrl + T` and then
   `Ctrl + X`.