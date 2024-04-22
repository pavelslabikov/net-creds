import logging
import re
from typing import Optional

from net_creds.models import Credentials
from net_creds.utils import double_line_checker

ftp_user_re = r'USER (.+)\r\n'
ftp_pw_re = r'PASS (.+)\r\n'


def parse_ftp(full_load, dst_ip_port, src_ip_port) -> Optional[Credentials]:
    '''
    Parse out FTP creds
    '''
    creds = None
    # Sometimes FTP packets double up on the authentication lines
    # We just want the lastest one. Ex: "USER danmcinerney\r\nUSER danmcinerney\r\n"
    full_load = double_line_checker(full_load, 'USER')

    # FTP and POP potentially use idential client > server auth pkts
    ftp_user = re.match(ftp_user_re, full_load)
    ftp_pass = re.match(ftp_pw_re, full_load)

    if ftp_user:
        creds = Credentials(src_ip_port, dst_ip_port, 'FTP User: %s' % ftp_user.group(1).strip())
        if dst_ip_port[-3:] != ':21':
            logging.info(f'[{src_ip_port} -> {dst_ip_port}] Nonstandard FTP port, confirm the service that is running on it')

    elif ftp_pass:
        creds = Credentials(src_ip_port, dst_ip_port, 'FTP Pass: %s' % ftp_pass.group(1).strip())
        if dst_ip_port[-3:] != ':21':
            logging.info(f'[{src_ip_port} -> {dst_ip_port}] Nonstandard FTP port, confirm the service that is running on it')

    return creds

