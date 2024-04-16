import logging
import os
import re

W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan


def printer(src_ip_port, dst_ip_port, msg):
    if dst_ip_port is not None:
        print_str = '[%s > %s] %s%s%s' % (src_ip_port, dst_ip_port, T, msg, W)
        # All credentials will have dst_ip_port, URLs will not

        print(print_str)

        # Escape colors like whatweb has
        ansi_escape = re.compile(r'\x1b[^m]*m')
        print_str = ansi_escape.sub('', print_str)

        # Log the creds
        logging.info(print_str)
    else:
        print_str = '[%s] %s' % (src_ip_port.split(':')[0], msg)
        print(print_str)
