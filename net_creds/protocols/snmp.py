from typing import Optional

from net_creds.models import Credentials


def parse_snmp(src_ip_port, dst_ip_port, snmp_layer) -> Optional[Credentials]:
    '''
    Parse out the SNMP version and community string
    '''
    creds = None
    if type(snmp_layer.community.val) == str:
        ver = snmp_layer.version.val
        msg = 'SNMPv%d community string: %s' % (ver, snmp_layer.community.val)
        creds = Credentials(src_ip_port, dst_ip_port, msg)
    return creds
