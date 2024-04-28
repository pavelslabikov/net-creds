import re
from typing import Optional

from net_creds.models import Credentials

irc_user_re = r'NICK (.+)'
irc_pw_re3 = r'PASS (.+)'


def parse_irc(packet_payload, pkt, dst_ip_port, src_ip_port) -> Optional[Credentials]:
    '''
    Find IRC logins
    '''
    creds = None
    if dst_ip_port[-3:] == ':21':
        return creds
    user_search = re.match(irc_user_re, packet_payload)
    pass_search3 = re.search(irc_pw_re3, packet_payload)
    msg = None
    if user_search:
        msg = 'IRC nick: %s' % user_search.group(1)
    if pass_search3:
        msg = 'IRC pass: %s' % pass_search3.group(1)
    if msg is not None:
        creds = Credentials(src_ip_port, dst_ip_port, msg.rstrip("\r\n"))
    return creds
