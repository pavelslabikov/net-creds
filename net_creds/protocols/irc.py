import re

from net_creds.output import printer

irc_user_re = r'NICK (.+?)((\r)?\n|\s)'
irc_pw_re = r'NS IDENTIFY (.+)'
irc_pw_re2 = 'nickserv :identify (.+)'


def irc_logins(full_load, pkt, dst_ip_port, src_ip_port):
    '''
    Find IRC logins
    '''
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
        printer(src_ip_port, dst_ip_port, msg)
