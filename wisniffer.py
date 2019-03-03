#!/bin/python3
import argparse
import subprocess
import re
import random
from scapy.all import *

macRegExp = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')


def main():
    parser = argparse.ArgumentParser(
        description='''Wi-Sniffer sniffs the data, packets from access
                       points.'''
    )
    parser.add_argument('-s', '--scan', action='store_true',
                        help='Scan for Access Points in range')
    parser.add_argument('-b', '--bssid', type=macaddr, metavar='',
                        help='BSSID i.e. MAC address of an access point')
    parser.add_argument('-e', '--essid', type=str, metavar='',
                        help='ESSID i.e. access point name')
    parser.add_argument('-i', '--iface', type=str, metavar='', required=True,
                        help='Interface to sniff')
    parser.add_argument('-d', '--deauth', type=int, metavar='',
                        help='Deauth probe to a AP or a client')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Timeout for sniffing( Default = 10)')
    parser.add_argument('-o', '--output', type=str, metavar='',
                        help='Output to a file')
    parser.add_argument('-v', '--verboose', action='store_true',
                        help='Verboose output')

    global args
    args = parser.parse_args()
    proc = subprocess.run(['ip', 'link', 'show'], stdout=subprocess.PIPE)
    output = proc.stdout.decode('utf-8')
    output = output.split('\n')
    ifaceList = []
    for i in output:
        temp = i.split(' ')
        if(len(temp) > 1):
            if(temp[1] != ''):
                ifaceList.append(temp[1][0:-1])
    if(args.iface in ifaceList):
        if(args.scan is True):
            scanAp()
        elif (args.bssid or args.essid):
            scanClients()
    else:
        print('Interface is not connected at present.')


def macaddr(s, pat=macRegExp):
    if not pat.match(s):
        print('''MAC address should be in format
                 XX:XX:XX:XX:XX:XX [0-9 a-f A-F]''')
        raise argparse.ArgumentTypeError
    return s


def println(msg):
    if args.verboose is True:
        print(msg)


def scanApPkt(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            bssid = pkt.addr2
            if bssid and (bssid not in wifiDict.keys()):
                wifiDict[bssid] = pkt.info
                ssid = pkt.info.decode('utf-8')
                channel = int(ord(pkt[Dot11Elt:3].info.decode('utf-8')))
                print(bssid + ' ' + str(channel) + ' ' + ssid + ' ')


def scanAp():
    global wifiDict
    wifiDict = {}
    i = 0
    print(' '*6+'BSSID' + ' '*7 + 'CH' + ' '*2 + 'SSID' + ' '*2)
    while(True):
        if i < 13:
            subprocess.run(['iw', 'dev', args.iface, 'set', 'channel',
                            str(i+1)])
        else:
            i = 0
            subprocess.run(['iw', 'dev', args.iface, 'set', 'channel',
                            str(i+1)])
        try:
            sniff(iface=args.iface, count=1, prn=scanApPkt,
                  timeout=args.timeout)
        except KeyboardInterrupt:
            break
        i = i+1
    else:
        print('while is over')


def scanClients():
    if args.bssid:
        while True:
            sniff(iface=args.iface, count=1, prn=scanClientsPkt)


def scanClientsPkt(pkt):
    global clients
    clients = []
    if pkt.haslayer(Dot11):
        if pkt.type == 2 and pkt.haslayer(EAPOL):
            print(pkt.addr2 + ' ' + pkt.addr1)
            if (pkt.addr1 not in clients and pkt.addr2 == args.bssid):
                clients.append(pkt.addr2)
                print('{0} {1}'.format(len(clients),
                                       pkt.addr2))


if __name__ == '__main__':
    main()
