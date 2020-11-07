# Modbus RTU sniffer

A sniffer for the Modbus RTU protocol.

This programs allows you to snif packets from a Modbus RTU serial
comunication and save them in a .pcap file that you can open with
a program like Wireshark.

## Usage

Compile the program with `make`. The only dependency is a C compiler
and a POSIX operating system.

You can specify the options with the command line:

```
Usage: ./sniffer [-h] [-o out_dir] [-p port] [-s speed]
                 [-P parity] [-S stop_bits] [-b bits]

 -o, --output-dir   directory where to save the output
 -p, --serial-port  serial port to use
 -s, --speed        serial port speed (default 9600)
 -b, --bits         number of bits (default 8)
 -P, --parity       parity to use (default 'N')
 -S, --stop-bits    stop bits to use (default 1)
```

By default files are saved in the output directory with filename in
the format `modbus_YYYY-mm-dd_HH:MM:SS.pcap`.

By sending to the program a `SIGUSR1` the capture is rotated, i.e. the pcap
file is closed and another one is initiated. By default a .pcap file contains
maximum 10000 entries: after that the log is rotate. You can tweak this parameter
by editing the `MAX_CAPTURE_FILE_PACKETS` in the source code.

To capture the packets, you need a standard RS485 to TTL serial converter.
I tested the capture on a Raspberry Pi model 3B+. If you also use
a Raspberry, make sure to enable the hardware UART for better performance
by disabling the Bluetooth interface.
