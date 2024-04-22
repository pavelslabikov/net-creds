import re
from typing import Optional

from net_creds.models import Credentials

irc_user_re = r'NICK (.+?)((\r)?\n|\s)'
irc_pw_re = r'NS IDENTIFY (.+)'
irc_pw_re2 = 'nickserv :identify (.+)'


def parse_irc(full_load, pkt, dst_ip_port, src_ip_port) -> Optional[Credentials]:
    '''
    Find IRC logins
    '''
    creds = None
    user_search = re.match(irc_user_re, full_load)
    pass_search = re.match(irc_pw_re, full_load)
    pass_search2 = re.search(irc_pw_re2, full_load.lower())
    msg = None
    if user_search:
        msg = 'IRC nick: %s' % user_search.group(1)
    if pass_search:
        msg = 'IRC pass: %s' % pass_search.group(1)
    if pass_search2:
        msg = 'IRC pass: %s' % pass_search2.group(1)
    if msg is not None:
        creds = Credentials(src_ip_port, dst_ip_port, msg)
    return creds
