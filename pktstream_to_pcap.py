#!/usr/bin/python

# -*- coding: utf-8 -*-
# @Author: lorenzo
# @Date:   2019-01-08 22:02:25
# @Last Modified by:   lorenzo
# @Last Modified time: 2019-03-09 16:54:53

# ./pktstream_to_pcap.py -s /dev/ttyUSB0
# ./pktstream_to_pcap.py -f captured.txt

import os
import sys
import signal
import time
import subprocess
import datetime
import serial

def save_acquired():
    out_folder = datetime.datetime.now().strftime("%Y%02m%02d%H%M%S")
    if not os.path.exists(out_folder):
        os.makedirs(out_folder)
    os.chdir(out_folder)

    pcap_list = []
    # convert each packet according to text2pcap format
    for pkt_i, packet_buffer in enumerate(packets_buffer):
        with open('pkt%02d_dump.txt' % pkt_i, 'w+') as ww:
            ww.write('000000 ')
            for i, byte in enumerate(packet_buffer):
                ww.write('%02x ' % byte)
                if i % 8 == 7:
                    ww.write('........\n')
                    ww.write('%06x ' % (i + 1))
        subprocess.run('text2pcap pkt%02d_dump.txt pkt%02d_dump.pcap' % (pkt_i, pkt_i), shell=True)
        pcap_list.append('pkt%02d_dump.pcap' % pkt_i)
        os.remove('pkt%02d_dump.txt' % pkt_i)
    # -a to concatenate instead of merging since we did not put timestamp to order
    subprocess.run('mergecap -a -w acquisition.pcap %s' % ' '.join(pcap_list), shell=True)

def stop_acquiring(x, y):
    print('> Stop acquiring...')
    save_acquired()
    sys.exit(0)


acquisition_start = time.time()
buffering = False
packets_buffer = []
stream_has_end = False

if sys.argv[1] == '-s':
    serial_port = sys.argv[2]
    stream_ch = serial.Serial(serial_port, baudrate=115200)
    signal.signal(signal.SIGINT, stop_acquiring)

elif sys.argv[1] == '-f':
    file_name = sys.argv[2]
    stream_ch = open(file_name, 'rb')
    stream_ch.seek(0, os.SEEK_END)
    stream_has_end = stream_ch.tell()
    stream_ch.seek(0)

else:
    sys.exit(1)

# parse bytes stream output
while True:
    line = stream_ch.readline().decode('utf-8').strip()

    if not line:
        if stream_has_end and stream_ch.tell() == stream_has_end:
                print('> Stop acquiring...')
                save_acquired()
                sys.exit(0)
        else:
            continue

    if line.startswith('PKTPKTs'):
        packets_buffer.append(bytearray())
        buffering = True
        continue
    if line.startswith('PKTPKTe') and buffering:
        buffering = False
        continue

    if buffering:
        new_packet = bytearray([int(byte, base=16) for byte in line.split(' ')])
        packets_buffer[-1].extend(new_packet)

        print('> Acquired %i packets in %i seconds' % (len(packets_buffer), time.time() - acquisition_start))

