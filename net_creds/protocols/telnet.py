from collections import OrderedDict
from typing import Optional

from net_creds.models import Credentials

telnet_stream = OrderedDict()


def parse_telnet(src_ip_port, dst_ip_port, load, ack, seq) -> Optional[Credentials]:
    '''
    Catch telnet logins and passwords
    '''
    global telnet_stream

    creds = None

    if src_ip_port in telnet_stream:
        # Do a utf decode in case the client sends telnet options before their username
        # No one would care to see that
        telnet_stream[src_ip_port] += load

        # \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
        if '\r' in telnet_stream[src_ip_port] or '\n' in telnet_stream[src_ip_port]:
            telnet_split = telnet_stream[src_ip_port].split(' ', 1)
            cred_type = telnet_split[0]
            value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
            # Create msg, the return variable
            msg = 'Telnet %s: %s' % (cred_type, value)
            creds = Credentials(src_ip_port, dst_ip_port, msg)
            del telnet_stream[src_ip_port]

    # This part relies on the telnet packet ending in
    # "login:", "password:", or "username:" and being <750 chars
    # Haven't seen any false+ but this is pretty general
    # might catch some eventually
    # maybe use dissector.py telnet lib?
    if len(telnet_stream) > 100:
        telnet_stream.popitem(last=False)
    mod_load = load.lower().strip()
    if mod_load.endswith('username:') or mod_load.endswith('login:'):
        telnet_stream[dst_ip_port] = 'username '
    elif mod_load.endswith('password:'):
        telnet_stream[dst_ip_port] = 'password '
    return creds
