# pktstream_to_pcap

Converts a packet stream (hex format with PKTPKTs and PKTPKTe strings to delimit packet start and end), from a file or a serial port, into pcap format.

    ./pktstream_to_pcap.py -s /dev/ttyUSB0
    ./pktstream_to_pcap.py -f captured.txt

Depends on `text2pcap` and `mergecap` tools.
Developed for educational purposes within the [IoT withit blog](https://iotwith.it/blog/).

