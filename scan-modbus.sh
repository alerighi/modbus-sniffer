#!/bin/bash
trap 'echo INT;exit' SIGINT

bauds=( 4800 9600 19200 38400 57600 115200 )
stopbits=( 1 2 )
parities=( N O E )
for baud in "${bauds[@]}"
do
    for stopbit in "${stopbits[@]}"
    do
      for parity in "${parities[@]}"
      do
        timeout -s INT 1 ./sniffer -l -p /dev/ttyUSB3 -s $baud -S $stopbit -P $parity --output output.pcap
      done
    done
done
