import argparse
import logging

from subprocess import Popen, PIPE, check_output
from sys import exit

import platform

import psutil
from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from net_creds.parser import parse_creds_from_packet

logging.basicConfig(level=logging.INFO)

system_platform = platform.system()

if system_platform != "Windows":
    from os import devnull, geteuid
    DN = open(devnull, 'w')


def parse_args():
    """Create the arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Choose an interface")
    parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
    parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address; -f 192.168.0.4")
    parser.add_argument("-v", "--verbose",
                        help="Display entire URLs and POST loads rather than truncating at 100 characters",
                        action="store_true")
    return parser.parse_args()


def auto_detect_iface():

    if system_platform == 'Linux':
        if geteuid():
            logging.error('[-] Please run as root')
            exit()
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    elif system_platform == "Windows":
        stats = psutil.net_if_stats()
        try:
            return list(stats.keys())[0]
        except IndexError:
            logging.error("[-] There are no up and running interfaces")
            exit()
    elif system_platform == 'Darwin':  # OSX support
        return check_output("route get 0.0.0.0 2>/dev/null| sed -n '5p' | cut -f4 -d' '", shell=True).rstrip()
    else:
        logging.error('[-] Could not find an internet active interface; please specify one with -i <interface>')
        exit()


if __name__ == "__main__":
    # Read packets from either pcap or interface
    args = parse_args()
    if args.pcap:
        try:

            for pkt in PcapReader(args.pcap):
                parse_creds_from_packet(pkt)
        except IOError:
            logging.error('[-] Could not open ' + args.pcap)
            exit()

    else:
        # Find the active interface
        if args.interface:
            iface = args.interface
        else:
            iface = auto_detect_iface()
        logging.info('[*] Using interface: ' + iface)

        if args.filterip:
            sniff(iface=iface, prn=parse_creds_from_packet, filter="not host %s" % args.filterip, store=0)
        else:
            sniff(iface=iface, prn=parse_creds_from_packet, store=0)
