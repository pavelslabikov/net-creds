import base64
import re
from collections import OrderedDict

from net_creds.output import printer
from net_creds.utils import double_line_checker

mail_auth_re = '(\d+ )?(auth|authenticate) (login|plain)'
mail_auth_re1 = '(\d+ )?login '

mail_auths = OrderedDict()


def mail_decode(src_ip_port, dst_ip_port, mail_creds):
    '''
    Decode base64 mail creds
    '''
    try:
        decoded = base64.b64decode(mail_creds).replace('\x00', ' ').decode('utf8')
        decoded = decoded.replace('\x00', ' ')
    except TypeError:
        decoded = None
    except UnicodeDecodeError as e:
        decoded = None

    if decoded != None:
        msg = 'Decoded: %s' % decoded
        printer(src_ip_port, dst_ip_port, msg)


def mail_logins(full_load, src_ip_port, dst_ip_port, ack, seq):
    '''
    Catch IMAP, POP, and SMTP logins
    '''
    # Handle the first packet of mail authentication
    # if the creds aren't in the first packet, save it in mail_auths

    # mail_auths = 192.168.0.2 : [1st ack, 2nd ack...]
    global mail_auths
    found = False

    # Sometimes mail packets double up on the authentication lines
    # We just want the lastest one. Ex: "1 auth plain\r\n2 auth plain\r\n"
    full_load = double_line_checker(full_load, 'auth')

    # Client to server 2nd+ pkt
    if src_ip_port in mail_auths:
        if seq in mail_auths[src_ip_port][-1]:
            stripped = full_load.strip('\r\n')
            try:
                decoded = base64.b64decode(stripped)
                msg = 'Mail authentication: %s' % decoded
                printer(src_ip_port, dst_ip_port, msg)
            except TypeError:
                pass
            mail_auths[src_ip_port].append(ack)

    # Server responses to client
    # seq always = last ack of tcp stream
    elif dst_ip_port in mail_auths:
        if seq in mail_auths[dst_ip_port][-1]:
            # Look for any kind of auth failure or success
            a_s = 'Authentication successful'
            a_f = 'Authentication failed'
            # SMTP auth was successful
            if full_load.startswith('235') and 'auth' in full_load.lower():
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_s)
                found = True
                try:
                    del mail_auths[dst_ip_port]
                except KeyError:
                    pass
            # SMTP failed
            elif full_load.startswith('535 '):
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_f)
                found = True
                try:
                    del mail_auths[dst_ip_port]
                except KeyError:
                    pass
            # IMAP/POP/SMTP failed
            elif ' fail' in full_load.lower():
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_f)
                found = True
                try:
                    del mail_auths[dst_ip_port]
                except KeyError:
                    pass
            # IMAP auth success
            elif ' OK [' in full_load:
                # Reversed the dst and src
                printer(dst_ip_port, src_ip_port, a_s)
                found = True
                try:
                    del mail_auths[dst_ip_port]
                except KeyError:
                    pass

            # Pkt was not an auth pass/fail so its just a normal server ack
            # that it got the client's first auth pkt
            else:
                if len(mail_auths) > 100:
                    mail_auths.popitem(last=False)
                mail_auths[dst_ip_port].append(ack)

    # Client to server but it's a new TCP seq
    # This handles most POP/IMAP/SMTP logins but there's at least one edge case
    else:
        mail_auth_search = re.match(mail_auth_re, full_load, re.IGNORECASE)
        if mail_auth_search != None:
            auth_msg = full_load
            # IMAP uses the number at the beginning
            if mail_auth_search.group(1) != None:
                auth_msg = auth_msg.split()[1:]
            else:
                auth_msg = auth_msg.split()
            # Check if its a pkt like AUTH PLAIN dvcmQxIQ==
            # rather than just an AUTH PLAIN
            if len(auth_msg) > 2:
                mail_creds = ' '.join(auth_msg[2:])
                msg = 'Mail authentication: %s' % mail_creds
                printer(src_ip_port, dst_ip_port, msg)

                mail_decode(src_ip_port, dst_ip_port, mail_creds)
                try:
                    del mail_auths[src_ip_port]
                except KeyError:
                    pass
                found = True

            # Mail auth regex was found and src_ip_port is not in mail_auths
            # Pkt was just the initial auth cmd, next pkt from client will hold creds
            if len(mail_auths) > 100:
                mail_auths.popitem(last=False)
            mail_auths[src_ip_port] = [ack]

        # At least 1 mail login style doesn't fit in the original regex:
        #     1 login "username" "password"
        # This also catches FTP authentication!
        #     230 Login successful.
        elif re.match(mail_auth_re1, full_load, re.IGNORECASE) != None:

            # FTP authentication failures trigger this
            # if full_load.lower().startswith('530 login'):
            #    return

            auth_msg = full_load
            auth_msg = auth_msg.split()
            if 2 < len(auth_msg) < 5:
                mail_creds = ' '.join(auth_msg[2:])
                msg = 'Authentication: %s' % mail_creds
                printer(src_ip_port, dst_ip_port, msg)
                mail_decode(src_ip_port, dst_ip_port, mail_creds)
                found = True

    if found == True:
        return True
