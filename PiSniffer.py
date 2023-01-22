# Author: Adam Robinson
# Version 2: Corrected way script handles AP-Responce (Probe Responces)
# Packet Capture script for use deployment on Raspberry Pi 3 running Kali Linux
# To be ran in conjunction with airodump-ng for channel switching

import csv
# device local time
import datetime
# pass arguments in terminal
import argparse
# Force utf8 encoding in logger from system
import sys
# Rotating Logger
import logging
from logging.handlers import RotatingFileHandler
# Library for reload function
from importlib import reload
# Convert UTC to local time with daylights saving
import pytz
# Serial input from GPS
import serial as s
# Handles GPS NMEA codes for lat/lon fields
import pynmea2
# Packet capture
from scapy.all import *

# Force USB GPS to be handled as serial device using teletype interface (BU-353 USB GPS)
GPSMessages = s.Serial("/dev/ttyACM0", 4800, timeout=5)

#reload(sys)
#sys.setdefaultencoding('utf8')

CSVDelim = ','
FoundAccessPoints = []

OUIMEM = {}
def new_func(OUIMEM, line):
    OUIMEM[line[0]] = line[1:]

with open('OUI.txt', 'r') as OUILookup:
    for line in csv.reader(OUILookup, delimiter='\t'):
        if not line or line[0] == "#":
            continue
        else:
            new_func(OUIMEM, line)

# Initialise GPS to North Pole
gpsLat = ['NO GPS']
gpsLon = ['NO GPS']

def gpsfix():
    while True:
        gps = GPSMessages.readline()
        if gps.startswith("$GPGGA"):
            return pynmea2.parse(gps)

def rssi(radiodata):
    if 'dBm_AntSignal=' in radiodata:
        start = radiodata.find('dBm_AntSignal=')
        return str(radiodata[start+14:start+21]).replace(' ','').replace('A','')
    else:
        return '-255dBm'

def channel(radiodata):
    if 'Channel=' in radiodata:
        start = radiodata.find('Channel=')
        freq = int(radiodata[start+8:start+12])
        if freq == 2412:
            return 'C:01 ' + str(freq)
        if freq == 2417:
            return 'C:02 ' + str(freq)
        if freq == 2422:
            return 'C:03 ' + str(freq)
        if freq == 2427:
            return 'C:04 ' + str(freq)
        if freq == 2432:
            return 'C:05 ' + str(freq)
        if freq == 2437:
            return 'C:06 ' + str(freq)
        if freq == 2442:
            return 'C:07 ' + str(freq)
        if freq == 2447:
            return 'C:08 ' + str(freq)
        if freq == 2452:
            return 'C:09 ' + str(freq)
        if freq == 2457:
            return 'C:10 ' + str(freq)
        if freq == 2462:
            return 'C:11 ' + str(freq)
        if freq == 2467:
            return 'C:12 ' + str(freq)
        if freq == 2472:
            return 'C:13 ' + str(freq)
        if freq == 2484:
            return 'C:14 ' + str(freq)
        else:
            return '-->>' + str(freq)

# Rotating logger and data formatting based on packet type
def probe_log_build(logger):
    def probe_handler(packet):

        radio = str(packet.mysummary)

        bst = pytz.timezone("Europe/London")
        date = str(datetime.now(bst).strftime('%Y-%m-%d'))
        clock = str(datetime.now(bst).isoformat().replace('T', '').split('.')[0])
        log_clock = clock[-8:]
        log_time = str(date + ' ' + log_clock)

        MAC = str(packet.addr2).upper()
        clientOUI = MAC[:8]
        firstOctet = clientOUI[:2]
        scale = 16
        num_of_bits = 8
        binaryRep = str(bin(int(firstOctet, scale))[2:].zfill(num_of_bits))

        if int(clock[-1:]) / 5 == 0:
            parsedGPS = gpsfix()
            if parsedGPS.latitude != 0.0 or parsedGPS.longitude != 0.0:
                gpsLat.append(str(parsedGPS.latitude))
                gpsLon.append(str(parsedGPS.longitude))

        if packet.haslayer(Dot11ProbeReq):
            probe = ['PR-REQ', rssi(radio), channel(radio) + 'Mhz', log_time,
                     str(gpsLat[-1])[:7], str(gpsLon[-1])[:7], 'Client', str(packet.addr2)]

            if OUIMEM.get(clientOUI) is not None:
                identifiers = len(OUIMEM[clientOUI])
                if identifiers == 2:
                    probe.append(str(OUIMEM[clientOUI][1]).replace(',', '').title())
                else:
                    if identifiers == 1:
                        probe.append(str(OUIMEM[clientOUI][0]).replace(',', '').title())
            else:
                if binaryRep[6:7] == '1':
                    probe.append('Locally Assigned')
                else:
                    probe.append('Unknown OUI')

            if '\x00' not in packet[Dot11ProbeReq].info:
                if str(packet.info):
                    probe.append(str(packet.info))
                else:
                    probe.append('Undirected Probe')

            logger.info(CSVDelim.join(probe))

        if packet.haslayer(Dot11Beacon):

            if str(packet[Dot11].addr3) not in FoundAccessPoints:
                beacon = ['AP-BEC', rssi(radio), channel(radio) + 'Mhz', log_time,
                           str(gpsLat[-1])[:7], str(gpsLon[-1])[:7], 'BSSID', str(packet[Dot11].addr3)]

                if OUIMEM.get(clientOUI) is not None:
                    identifiers = len(OUIMEM[clientOUI])
                    if identifiers == 2:
                        beacon.append(str(OUIMEM[clientOUI][1]).replace(',', '').title())
                    else:
                        if identifiers == 1:
                            beacon.append(str(OUIMEM[clientOUI][0]).replace(',', '').title())
                else:
                    if binaryRep[6:7] == '1':
                        beacon.append('Locally Assigned')
                    else:
                        beacon.append('Unknown OUI')

                beacon.append(str(packet[Dot11].info))
                FoundAccessPoints.append(str(packet[Dot11].addr3))
                logger.info(CSVDelim.join(beacon))

        if packet.haslayer(Dot11ProbeResp):
            response = ['AP-RES', rssi(radio), channel(radio) + 'Mhz', log_time,
                        str(gpsLat[-1])[:7], str(gpsLon[-1])[:7], 'Client', str(packet[Dot11].addr1), 'BSSID', str(packet[Dot11].addr3)]

            if OUIMEM.get(clientOUI) is not None:
                identifiers = len(OUIMEM[clientOUI])
                if identifiers == 2:
                    response.append(str(OUIMEM[clientOUI][1]).replace(',', '').title())
                else:
                    if identifiers == 1:
                        response.append(str(OUIMEM[clientOUI][0]).replace(',', '').title())
            else:
                if binaryRep[6:7] == '1':
                    response.append('Locally Assigned')
                else:
                    response.append('Unknown OUI')

            response.append(str(packet[Dot11].info))
            logger.info(CSVDelim.join(response))

        if DHCP in packet:
            DHCPFinger = ['DHCP', '??']
            logger.info(CSVDelim.join(DHCPFinger))


    return probe_handler

def main():
    # Arguments for terminal control
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--monitor')
    parser.add_argument('-f', '--file')
    args = parser.parse_args()

    if not args.monitor:
        print ("Monitor mode adapter not set")
        sys.exit(-1)

    if not args.file:
        print ("Output location not set")
        sys.exit(-1)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    #Output location
    handler = RotatingFileHandler('data/' + str(args.file) + '.csv')
    logger.addHandler(handler)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    # Monitor mode device
    sniff(iface=args.monitor, prn=probe_log_build(logger), store=0)

if __name__ == '__main__':
    main()
