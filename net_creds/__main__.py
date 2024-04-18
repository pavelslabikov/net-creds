import argparse
from os import devnull
from subprocess import Popen, PIPE, check_output
from sys import exit

import platform

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from net_creds.parser import parse_creds_from_packet

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
    system_platform = platform.system()
    if system_platform == 'Linux':
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    elif system_platform == 'Darwin':  # OSX support
        return check_output("route get 0.0.0.0 2>/dev/null| sed -n '5p' | cut -f4 -d' '", shell=True).rstrip()
    else:
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')


if __name__ == "__main__":
    ##################### DEBUG ##########################
    ## Hit Ctrl-C while program is running and you can see
    ## whatever variable you want within the IPython cli
    ## Don't forget to uncomment IPython in imports
    # def signal_handler(signal, frame):
    #    embed()
    ##    sniff(iface=conf.iface, prn=pkt_parser, store=0)
    #    sys.exit()
    # signal.signal(signal.SIGINT, signal_handler)
    ######################################################

    # Read packets from either pcap or interface
    args = parse_args()
    if args.pcap:
        try:

            for pkt in PcapReader(args.pcap):
                parse_creds_from_packet(pkt)
        except IOError:
            exit('[-] Could not open %s' % args.pcap)

    else:
        # Check for root
        # if geteuid():
        #     exit('[-] Please run as root')

        # Find the active interface
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = auto_detect_iface()
        print('[*] Using interface:', conf.iface)

        if args.filterip:
            sniff(iface=conf.iface, prn=parse_creds_from_packet, filter="not host %s" % args.filterip, store=0)
        else:
            sniff(iface=conf.iface, prn=parse_creds_from_packet, store=0)
