#!/usr/bin/env python3

import logging
from typing import Optional

from scapy.layers.inet import UDP, IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.kerberos import Kerberos
from scapy.layers.snmp import SNMP

from net_creds.models import Credentials
from net_creds.protocols.ftp import parse_ftp
from net_creds.protocols.http import parse_http_load
from net_creds.protocols.irc import parse_irc
from net_creds.protocols.kerberos import parse_udp_kerberos, \
    parse_tcp_kerberos
from net_creds.protocols.mail import parse_mail
from net_creds.protocols.ntlm import parse_netntlm, parse_nonnet_ntlm
from net_creds.protocols.snmp import parse_snmp
from net_creds.protocols.telnet import parse_telnet

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.l2 import *

conf.verb = 0
from collections import OrderedDict

logging.basicConfig(filename='../credentials.txt', level=logging.INFO)
pkt_frag_loads = OrderedDict()


def remove_frags_if_necessary():
    '''
    Keep the FILO OrderedDict of frag loads from getting too large
    3 points of limit:
        Number of ip_ports < 50
        Number of acks per ip:port < 25
        Number of chars in load < 5000
    '''
    global pkt_frag_loads

    # Keep the number of IP:port mappings below 50
    # last=False pops the oldest item rather than the latest
    while len(pkt_frag_loads) > 50:
        pkt_frag_loads.popitem(last=False)

    # Loop through a deep copy dict but modify the original dict
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        if len(copy_pkt_frag_loads[ip_port]) > 0:
            # Keep 25 ack:load's per ip:port
            while len(copy_pkt_frag_loads[ip_port]) > 25:
                pkt_frag_loads[ip_port].popitem(last=False)

    # Recopy the new dict to prevent KeyErrors for modifying dict in loop
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        # Keep the load less than 75,000 chars
        for ack in copy_pkt_frag_loads[ip_port]:
            # If load > 5000 chars, just keep the last 200 chars
            if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
                pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]


def join_frags(ack, src_ip_port, load):
    '''
    Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
    '''
    for ip_port in pkt_frag_loads:
        if src_ip_port == ip_port:
            if ack in pkt_frag_loads[src_ip_port]:
                # Make pkt_frag_loads[src_ip_port][ack] = full load
                old_load = pkt_frag_loads[src_ip_port][ack]
                concat_load = old_load + load
                return OrderedDict([(ack, concat_load)])

    return OrderedDict([(ack, load)])


def parse_creds_from_packet(pkt: Packet):
    '''
    Start parsing packets here
    '''
    global pkt_frag_loads

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return

    if not pkt.haslayer(IP):
        return

    creds_list = extract_creds(pkt)
    for cred in creds_list:
        # Escape colors like whatweb has
        ansi_escape = re.compile(r'\x1b[^m]*m')
        print_str = ansi_escape.sub('', str(cred))
        logging.info(print_str)


def extract_creds(pkt: Packet) -> List[Credentials]:
    # UDP
    if pkt.haslayer(UDP):

        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)

        # SNMP community strings
        if pkt.haslayer(SNMP):
            return [parse_snmp(src_ip_port, dst_ip_port, pkt[SNMP])]

        # Kerberos over UDP
        if pkt.haslayer(Kerberos):
            return [parse_udp_kerberos(src_ip_port, dst_ip_port, pkt)]


    # TCP
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        creds_list = []

        ack = str(pkt[TCP].ack)
        seq = str(pkt[TCP].seq)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
        remove_frags_if_necessary()

        try:
            load_decoded = pkt[Raw].load.decode("UTF-8")
        except UnicodeDecodeError:
            return creds_list

        pkt_frag_loads[src_ip_port] = join_frags(ack, src_ip_port, load_decoded)
        full_load = pkt_frag_loads[src_ip_port][ack]

        # Limit the packets we regex to increase efficiency
        # 750 is a bit arbitrary but some SMTP auth success pkts
        # are 500+ characters
        if 0 < len(full_load) < 750:
            creds_list.append(parse_ftp(full_load, dst_ip_port, src_ip_port))
            creds_list.append(parse_mail(full_load, src_ip_port, dst_ip_port, ack, seq))
            creds_list.append(parse_irc(full_load, pkt, dst_ip_port, src_ip_port))
            creds_list.append(parse_telnet(src_ip_port, dst_ip_port, load_decoded, ack, seq))

        creds_list.append(parse_http_load(full_load, src_ip_port, dst_ip_port))
        creds_list.append(parse_tcp_kerberos(src_ip_port, dst_ip_port, pkt))
        creds_list.append(parse_nonnet_ntlm(full_load, ack, seq, src_ip_port, dst_ip_port))
        creds_list.append(parse_netntlm(full_load, ack, seq, src_ip_port, dst_ip_port))
        return creds_list
