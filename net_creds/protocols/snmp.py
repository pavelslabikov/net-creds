from net_creds.output import printer


def parse_snmp(src_ip_port, dst_ip_port, snmp_layer):
    '''
    Parse out the SNMP version and community string
    '''
    if type(snmp_layer.community.val) == str:
        ver = snmp_layer.version.val
        msg = 'SNMPv%d community string: %s' % (ver, snmp_layer.community.val)
        printer(src_ip_port, dst_ip_port, msg)
    return True
