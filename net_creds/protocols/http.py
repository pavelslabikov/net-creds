import base64
import logging
import re
from typing import Optional
from urllib.parse import unquote

from net_creds.models import Credentials

http_search_re = '((search|query|&q|\?q|search\?p|searchterm|keywords|keyword|command|terms|keys|question|kwd|searchPhrase)=([^&][^&]*))'

authenticate_re = '(www-|proxy-)?authenticate'
authorization_re = '(www-|proxy-)?authorization'


def get_http_searches(http_url_req, body, host):
    '''
    Find search terms from URLs. Prone to false positives but rather err on that side than false negatives
    search, query, ?s, &q, ?q, search?p, searchTerm, keywords, command
    '''
    false_pos = ['i.stack.imgur.com']

    searched = None
    if http_url_req != None:
        searched = re.search(http_search_re, http_url_req, re.IGNORECASE)
        if searched == None:
            searched = re.search(http_search_re, body, re.IGNORECASE)

    if searched != None and host not in false_pos:
        searched = searched.group(3)
        # Eliminate some false+
        try:
            # if it doesn't decode to utf8 it's probably not user input
            searched = searched.decode('utf8')
        except UnicodeDecodeError:
            return
        # some add sites trigger this function with single digits
        if searched in [str(num) for num in range(0, 10)]:
            return
        # nobody's making >100 character searches
        if len(searched) > 100:
            return
        msg = 'Searched %s: %s' % (host, unquote(searched.encode('utf8')).replace('+', ' '))
        return msg


def parse_basic_auth(src_ip_port, dst_ip_port, headers, authorization_header) -> Optional[Credentials]:
    '''
    Parse basic authentication over HTTP
    '''
    creds = None
    if authorization_header:
        # authorization_header sometimes is triggered by failed ftp
        try:
            header_val = headers[authorization_header.group()]
        except KeyError:
            return
        b64_auth_re = re.match('basic (.+)', header_val, re.IGNORECASE)
        if b64_auth_re != None:
            basic_auth_b64 = b64_auth_re.group(1)
            try:
                basic_auth_creds = base64.b64decode(basic_auth_b64).decode("UTF-8")
            except Exception:
                return
            msg = 'Basic Authentication: %s' % basic_auth_creds
            creds = Credentials(src_ip_port, dst_ip_port, msg)
    return creds

def get_http_url(method, host, path, headers):
    '''
    Get the HTTP method + URL from requests
    '''
    if method != None and path != None:

        # Make sure the path doesn't repeat the host header
        if host != '' and not re.match('(http(s)?://)?' + host, path):
            http_url_req = method + ' ' + host + path
        else:
            http_url_req = method + ' ' + path

        http_url_req = url_filter(http_url_req)

        return http_url_req


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


def parse_http_line(http_line, http_methods):
    '''
    Parse the header with the HTTP method in it
    '''
    http_line_split = http_line.split()
    method = ''
    path = ''

    # Accounts for pcap files that might start with a fragment
    # so the first line might be just text data
    if len(http_line_split) > 1:
        method = http_line_split[0]
        path = http_line_split[1]

    # This check exists because responses are much different than requests e.g.:
    #     HTTP/1.1 407 Proxy Authentication Required ( Access is denied.  )
    # Add a space to method because there's a space in http_methods items
    # to avoid false+
    if method + ' ' not in http_methods:
        method = None
        path = None

    return method, path


def parse_http_load(full_load, src_ip_port, dst_ip_port) -> Optional[Credentials]:
    '''
    Split the raw load into list of headers and body string
    '''
    creds = None
    http_methods = ['GET ', 'POST ', 'CONNECT ', 'TRACE ', 'TRACK ', 'PUT ', 'DELETE ', 'HEAD ']
    try:
        headers, body = full_load.split("\r\n\r\n", 1)
    except ValueError:
        headers = full_load
        body = ''
    header_lines = headers.split("\r\n")

    # Pkts may just contain hex data and no headers in which case we'll
    # still want to parse them for usernames and password
    http_line = get_http_line(header_lines, http_methods)
    if not http_line:
        headers = ''
        body = full_load

    header_lines = [line for line in header_lines if line != http_line]

    headers = headers_to_dict(header_lines)
    if 'host' in headers:
        host = headers['host']
    else:
        host = ''

    if http_line != None:
        method, path = parse_http_line(http_line, http_methods)
        http_url_req = get_http_url(method, host, path, headers)
        if http_url_req != None:
            logging.info(f'[{src_ip_port.split(":")[0]}] {http_url_req}')

    # Print user/pwds
    if body != '':
        user_passwd = get_login_pass(body)
        if user_passwd != None:
            try:
                http_user = user_passwd[0].decode('utf8')
                http_pass = user_passwd[1].decode('utf8')
                # Set a limit on how long they can be prevent false+
                if len(http_user) > 75 or len(http_pass) > 75:
                    return
                creds = Credentials(src_ip_port, dst_ip_port, f'HTTP authentication: {http_user}:{http_pass}')
            except UnicodeDecodeError:
                pass

    # Look for authentication headers

    authenticate_header = None
    authorization_header = None
    for header in headers:
        authenticate_header = re.match(authenticate_re, header)
        authorization_header = re.match(authorization_re, header)
        if authenticate_header or authorization_header:
            break

    # Basic Auth
    if authorization_header or authenticate_header:
        return parse_basic_auth(src_ip_port, dst_ip_port, headers, authorization_header)

    return creds


def get_http_line(header_lines, http_methods):
    '''
    Get the header with the http command
    '''
    for header in header_lines:
        for method in http_methods:
            # / is the only char I can think of that's in every http_line
            # Shortest valid: "GET /", add check for "/"?
            if header.startswith(method):
                http_line = header
                return http_line


def url_filter(http_url_req):
    '''
    Filter out the common but uninteresting URLs
    '''
    if http_url_req:
        d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
        if any(http_url_req.endswith(i) for i in d):
            return

    return http_url_req


def get_login_pass(body):
    '''
    Regex out logins and passwords from a string
    '''
    user = None
    passwd = None

    # Taken mainly from Pcredz by Laurent Gaffie
    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for login in userfields:
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for passfield in passfields:
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group()

    if user and passwd:
        return (user, passwd)
