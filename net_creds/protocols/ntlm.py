import base64
import binascii
import re
import struct
from collections import OrderedDict

from net_creds.output import printer

challenge_acks = OrderedDict()
NTLMSSP2_re = 'NTLMSSP\x00\x02\x00\x00\x00.+'
NTLMSSP3_re = 'NTLMSSP\x00\x03\x00\x00\x00.+'

authenticate_re = '(www-|proxy-)?authenticate'
authorization_re = '(www-|proxy-)?authorization'


def parse_nonnet_ntlm(full_load, ack, seq, src_ip_port, dst_ip_port):
    # Non-NETNTLM NTLM hashes (MSSQL, DCE-RPC,SMBv1/2,LDAP, MSSQL)
    NTLMSSP2 = re.search(NTLMSSP2_re, full_load, re.DOTALL)
    NTLMSSP3 = re.search(NTLMSSP3_re, full_load, re.DOTALL)
    msg = None
    if NTLMSSP2:
        parse_challenge(NTLMSSP2.group(), ack)
    if NTLMSSP3:
        msg = parse_ntlm_resp(NTLMSSP3.group(), seq)

    if msg is not None:
        printer(src_ip_port, dst_ip_port, msg)


def parse_netntlm(full_load, ack, seq, src_ip_port, dst_ip_port):
    '''
    Parse NTLM hashes out
    '''
    try:
        headers, body = full_load.split("\r\n\r\n", 1)
    except ValueError:
        headers = full_load
        body = ''
    header_lines = headers.split("\r\n")
    headers = headers_to_dict(header_lines)

    authenticate_header = None
    authorization_header = None
    for header in headers:
        authenticate_header = re.match(authenticate_re, header)
        authorization_header = re.match(authorization_re, header)
        if authenticate_header or authorization_header:
            break

    msg = None
    # Type 2 challenge from server
    if authenticate_header != None:
        chal_header = authenticate_header.group()
        parse_netntlm_chal(headers, chal_header, ack)

    # Type 3 response from client
    elif authorization_header != None:
        resp_header = authorization_header.group()
        msg = parse_netntlm_resp_msg(headers, resp_header, seq)

    if msg != None:
        printer(src_ip_port, dst_ip_port, msg)


def headers_to_dict(header_lines):
    '''
    Convert the list of header lines into a dictionary
    '''
    headers = {}
    for line in header_lines:
        lineList = line.split(': ', 1)
        key = lineList[0].lower()
        if len(lineList) > 1:
            headers[key] = lineList[1]
        else:
            headers[key] = ""
    return headers


def parse_netntlm_chal(headers, chal_header, ack):
    '''
    Parse the netntlm server challenge
    https://code.google.com/p/python-ntlm/source/browse/trunk/python26/ntlm/ntlm.py
    '''
    try:
        header_val2 = headers[chal_header]
    except KeyError:
        return
    header_val2 = header_val2.split(' ', 1)
    # The header value can either start with NTLM or Negotiate
    if header_val2[0] == 'NTLM' or header_val2[0].lower() == 'negotiate':
        try:
            msg2 = header_val2[1]
        except IndexError:
            return
        msg2 = base64.b64decode(msg2).decode("UTF-8")
        parse_challenge(msg2, ack)


def parse_challenge(msg2, ack):
    '''
    Parse server challenge
    '''
    global challenge_acks

    Signature = msg2[0:8]
    try:
        msg_type = struct.unpack("<I", msg2[8:12])[0]
        assert (msg_type == 2)
    except Exception:
        return
    ServerChallenge = msg2[24:32].encode('hex')

    # Keep the dict of ack:challenge to less than 50 chals
    if len(challenge_acks) > 50:
        challenge_acks.popitem(last=False)
    challenge_acks[ack] = ServerChallenge


def parse_netntlm_resp_msg(headers, resp_header, seq):
    '''
    Parse the client response to the challenge
    '''
    try:
        header_val3 = headers[resp_header]
    except KeyError:
        return
    header_val3 = header_val3.split(' ', 1)

    # The header value can either start with NTLM or Negotiate
    if header_val3[0] == 'NTLM' or header_val3[0] == 'Negotiate':
        try:
            msg3 = base64.b64decode(header_val3[1]).decode("UTF-8")
        except UnicodeDecodeError:
            return
        return parse_ntlm_resp(msg3, seq)


def parse_ntlm_resp(msg3, seq):
    '''
    Parse the 3rd msg in NTLM handshake
    Thanks to psychomario
    '''

    if seq in challenge_acks:
        challenge = challenge_acks[seq]
    else:
        challenge = 'CHALLENGE NOT FOUND'

    msg = None
    if len(msg3) > 43:
        # Thx to psychomario for below
        lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack(
            "12xhhihhihhihhi", msg3[:44])
        lmhash = binascii.b2a_hex(msg3[lmoff:lmoff + lmlen])
        nthash = binascii.b2a_hex(msg3[ntoff:ntoff + ntlen])
        domain = msg3[domoff:domoff + domlen].replace("\0", "")
        user = msg3[useroff:useroff + userlen].replace("\0", "")
        # Original check by psychomario, might be incorrect?
        # if lmhash != "0"*48: #NTLMv1
        if ntlen == 24:  # NTLMv1
            msg = '%s %s' % ('NETNTLMv1:', user + "::" + domain + ":" + lmhash + ":" + nthash + ":" + challenge)
        elif ntlen > 60:  # NTLMv2
            msg = '%s %s' % (
            'NETNTLMv2:', user + "::" + domain + ":" + challenge + ":" + nthash[:32] + ":" + nthash[32:])
    return msg
