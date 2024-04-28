import unittest
from typing import List

import pytest
from scapy.utils import PcapReader

from net_creds.models import Credentials
import net_creds.parser as parser
import os.path


@pytest.mark.parametrize(
    "pcap_filename, expected_creds",
    [
        ("ftp.pcap", [
            "[81.131.67.131:1026 -> 192.88.99.1:21] FTP User: anonymous",
            "[81.131.67.131:1026 -> 192.88.99.1:21] FTP Pass: IEUser@"
        ]),

        ("http_basic.pcap", [
            "[192.168.88.22:2063 -> 52.203.147.106:80] Basic Authentication: user:P@ssw0rd"
        ]),

        ("irc.pcap", [
            "[192.168.88.22:2445 -> 51.161.82.214:6667] IRC pass: 123",
            "[192.168.88.22:2445 -> 51.161.82.214:6667] IRC nick: pslab"
        ]),

        ("pop3.pcap", [
            "[192.168.0.4:26284 -> 212.227.15.166:110] Mail authentication:  digitalinvestigator@networksims.com napier",
            "[192.168.0.4:26308 -> 212.227.15.166:110] Mail authentication:  digitalinvestigator@networksims.com napier123",
            "[192.168.0.4:26383 -> 212.227.15.166:110] Mail authentication:  digitalinvestigator@networksims.com napier123"
        ]),

        ("telnet.pcap", [
            "[192.168.0.2:1550 -> 192.168.0.1:23] Telnet username: fake",
            "[192.168.0.2:1550 -> 192.168.0.1:23] Telnet password: user"
        ])

    ]
)
def test_parsing_pcap_file(pcap_filename: str, expected_creds: List[str]):
    parser.result_creds_list.clear()
    for pkt in PcapReader("../pcap-examples/" + pcap_filename):
        parser.parse_creds_from_packet(pkt)
    assert list(map(str, parser.result_creds_list)) == expected_creds
