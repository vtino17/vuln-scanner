import ipaddress
import socket


class ScanTarget:

    def __init__(self, host, port, protocol="tcp"):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.service = None
        self.version = None
        self.status = "unknown"
        self.vulnerabilities = []

    def __repr__(self):
        return f"{self.host}:{self.port} ({self.service or 'unknown'})"


class TargetParser:

    @staticmethod
    def parse(target_str, ports_str="80,443,22"):
        targets = []
        ports = TargetParser._parse_ports(ports_str)

        try:
            network = ipaddress.ip_network(target_str, strict=False)
            hosts = [str(h) for h in network.hosts()]
        except ValueError:
            try:
                ipaddress.ip_address(target_str)
                hosts = [target_str]
            except ValueError:
                hosts = [socket.gethostbyname(target_str)]

        for host in hosts:
            for port in ports:
                targets.append(ScanTarget(host, port))

        return targets

    @staticmethod
    def _parse_ports(ports_str):
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
