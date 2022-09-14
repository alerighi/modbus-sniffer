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

 -o, --output       output file where to save the output
 -p, --serial-port  serial port to use
 -s, --speed        serial port speed (default 9600)
 -b, --bits         number of bits (default 8)
 -P, --parity       parity to use (default 'N')
 -S, --stop-bits    stop bits to use (default 1)
 -t, --interval     time interval between packets (default 1500)
 -l, --low-latency  try to enable serial port low-latency mode (Linux-only)
```

By default the output file is `stdout`. This allows to pipe directly the output into other
programs, such as Wireshark. 

Unlinke previous versions of the program, an output directory and files into them
are not created. If you need to do a long capture, splitting it into multiple caputure
files, you can use an external program, such as `logrotate` to create a copy of the output
file, and the send to this program `SIGUSR1` to reopen the capture file again. 

As an example, you can use the following logrotate config:
```
/path/to/capture.log {
    size 10K
    copy
    dateext
    dateformat "-%Y-%m-%d-%s"
    missingok
    postrotate
        killall -USR1 sniffer
    endscript
}
```

To capture the packets, you need a standard RS485 to TTL serial converter.
I tested the capture on a Raspberry Pi model 3B+. If you also use
a Raspberry, make sure to enable the hardware UART for better performance
by disabling the Bluetooth interface.

## USB Serial port latency

Linux kernel tries to optimize load of USB transfers, that's a latency_timer which is default 16ms.
It's pretty high for modbus communication, so to get better result use the `-l` (`--low-latency`) flag to try to set 
the serial port automatically to ASYNC_LOW_LATENCY (1ms). This requires root privileges, and it's supported only on Linux.
Moreover, not all serial adapters may be supported. In case it's not supported the program will print an error and continue in normal mode.
 