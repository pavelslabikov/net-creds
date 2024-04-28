class Credentials:
    def __eq__(self, __value):
        return (self.value == __value.value and self.src_ip_port == __value.src_ip_port
                and self.dst_ip_port == __value.dst_ip_port)

    def __init__(self, src_ip_port: str, dst_ip_port: str, value: str):
        self.src_ip_port = src_ip_port
        self.dst_ip_port = dst_ip_port
        self.value = value

    def __str__(self):
        return f"[{self.src_ip_port} -> {self.dst_ip_port}] {self.value}"

    def __repr__(self):
        return str(self)

    src_ip_port: str
    dst_ip_port: str
    value: str
