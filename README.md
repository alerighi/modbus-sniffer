# Modbus RTU sniffer

A sniffer for the Modbus RTU protocol.

This programs allows you to snif packets from a Modbus RTU serial
comunication and save them in a .pcap file that you can open with
a program like Wireshark.

## Usage

Compile the program with `make`. This program doesn't currently have
CLI arguments. To edit the parameters you must edit the source file
`sniffer.c`, in particular the serial port path and the relative, and
the capture output directory.

By default files are saved in the output directory with filename in
the format `modbus_YYYY-mm-dd_HH:MM:SS.pcap`.

To capture the packets, you need a standard RS485 to TTL serial converter.
I tested the capture on a Raspberry Pi model 3B+. If you also use
a Raspberry, make sure to enable the hardware UART for better performance
by disabling the Bluetooth interface.
