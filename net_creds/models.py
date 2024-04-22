from enum import Enum

W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan


class Credentials:
    def __init__(self, src_ip_port: str, dst_ip_port: str, value: str):
        self.src_ip_port = src_ip_port
        self.dst_ip_port = dst_ip_port
        self.value = value

    def __str__(self):
        return f"[{self.src_ip_port} -> {self.dst_ip_port}] {T}{self.value}{W}"

    src_ip_port: str
    dst_ip_port: str
    value: str
