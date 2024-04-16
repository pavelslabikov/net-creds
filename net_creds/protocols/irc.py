import re

irc_user_re = r'NICK (.+?)((\r)?\n|\s)'
irc_pw_re = r'NS IDENTIFY (.+)'
irc_pw_re2 = 'nickserv :identify (.+)'


def irc_logins(full_load, pkt):
    '''
    Find IRC logins
    '''
    user_search = re.match(irc_user_re, full_load)
    pass_search = re.match(irc_pw_re, full_load)
    pass_search2 = re.search(irc_pw_re2, full_load.lower())
    if user_search:
        msg = 'IRC nick: %s' % user_search.group(1)
        return msg
    if pass_search:
        msg = 'IRC pass: %s' % pass_search.group(1)
        return msg
    if pass_search2:
        msg = 'IRC pass: %s' % pass_search2.group(1)
        return msg
