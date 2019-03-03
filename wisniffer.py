#!/usr/bin/python3
import argparse
import subprocess
import re
import random
from scapy.all import *

clients = []

macRegExp = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')


def main():

    # Command-Line arguments
    parser = argparse.ArgumentParser(description='''WiSniffer is an wireless info gathering and snffing tool.
         Scan for Access Points and perform scans, deauthentications etc..,''')
    networkOpt = parser.add_argument_group('Network Options')
    networkOpt.add_argument('-b', '--bssid', type=macaddr, metavar='',
                            help='BSSID of an AP')
    networkOpt.add_argument('-e', '--essid', type=str, metavar='',
                            help='ESSID of an AP')
    networkOpt.add_argument('-c', '--channel', type=int, metavar='',
                            help='Channel of AP')
    networkOpt.add_argument('-i', '--iface', type=str, metavar='',
                            help='Interface to use for scanning')
    scanOpt = parser.add_argument_group('Scan Options')
    scanOpt.add_argument('-s', '--scan', action='store_true',
                         help='Scan all AP\'s in range')
    scanOpt.add_argument('-d', '--deauth', action='store_true',
                         help='Send de-authentication frames to AP')
    scanOpt.add_argument('-t', '--timeout', type=int,
                         help='Timeout for sniffing( Default = 10)')
    extraOpt = parser.add_argument_group('Extra Options')
    extraOpt.add_argument('-o', '--output', type=str, metavar='',
                          help='Output to a file')
    printOpt = extraOpt.add_mutually_exclusive_group()
    printOpt.add_argument('-q', '--quiet', action='store_true',
                          help='Scan quietly')
    printOpt.add_argument('-v', '--verboose', action='store_true',
                          help='print verboose')
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
            sys.exit(0)
        i = i+1
    else:
        print('while is over')


def scanClients():
    subprocess.run(['iw', 'dev', args.iface, 'set', 'channel',
                    str(args.channel)])
    if not args.quiet:
        print('BSSID: {0} CHANNEL: {1}'.format(args.bssid, args.channel))
    while True:
        try:
            sniff(iface=args.iface, count=10, prn=scanClientsPkt)
        except KeyboardInterrupt:
            sys.exit(0)


def scanClientsPkt(pkt):
    if pkt.haslayer(Dot11):
        pkt = pkt.getlayer(Dot11)
        if pkt.type == 2:
            if ((pkt.addr2 not in clients) and (pkt.addr1 == args.bssid)):
                clients.append(pkt.addr2)
                print('{0} {1}'.format(len(clients), pkt.addr2))


if __name__ == '__main__':
    main()
