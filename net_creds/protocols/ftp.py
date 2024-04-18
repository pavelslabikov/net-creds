import re

from net_creds.models import AuthData
from net_creds.output import printer
from net_creds.utils import double_line_checker

ftp_user_re = r'USER (.+)\r\n'
ftp_pw_re = r'PASS (.+)\r\n'


def parse_ftp(full_load, dst_ip_port, src_ip_port):
    '''
    Parse out FTP creds
    '''
    print_strs = []

    # Sometimes FTP packets double up on the authentication lines
    # We just want the lastest one. Ex: "USER danmcinerney\r\nUSER danmcinerney\r\n"
    full_load = double_line_checker(full_load, 'USER')

    # FTP and POP potentially use idential client > server auth pkts
    ftp_user = re.match(ftp_user_re, full_load)
    ftp_pass = re.match(ftp_pw_re, full_load)

    if ftp_user:
        msg1 = 'FTP User: %s' % ftp_user.group(1).strip()
        print_strs.append(msg1)
        if dst_ip_port[-3:] != ':21':
            msg2 = 'Nonstandard FTP port, confirm the service that is running on it'
            print_strs.append(msg2)

    elif ftp_pass:
        msg1 = 'FTP Pass: %s' % ftp_pass.group(1).strip()
        print_strs.append(msg1)
        if dst_ip_port[-3:] != ':21':
            msg2 = 'Nonstandard FTP port, confirm the service that is running on it'
            print_strs.append(msg2)

    for msg in print_strs:
        printer(src_ip_port, dst_ip_port, msg)

