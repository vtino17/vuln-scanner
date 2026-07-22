from vuln_scanner.core.target import TargetParser, ScanTarget


class TestTargetParser:

    def test_single_host(self):
        targets = TargetParser.parse("192.168.1.1", "80")
        assert len(targets) == 1
        assert targets[0].host == "192.168.1.1"
        assert targets[0].port == 80

    def test_multiple_ports(self):
        targets = TargetParser.parse("10.0.0.1", "80,443,22")
        assert len(targets) == 3
        ports = [t.port for t in targets]
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports

    def test_port_range(self):
        targets = TargetParser.parse("10.0.0.1", "80-82")
        assert len(targets) == 3
        ports = [t.port for t in targets]
        assert 80 in ports
        assert 81 in ports
        assert 82 in ports

    def test_cidr_scan(self):
        targets = TargetParser.parse("192.168.1.0/30", "22")
        assert len(targets) == 2
        for t in targets:
            assert t.port == 22

    def test_scan_target_creation(self):
        t = ScanTarget("10.0.0.1", 443)
        assert t.host == "10.0.0.1"
        assert t.port == 443
        assert t.protocol == "tcp"
        assert t.status == "unknown"


class TestScanTarget:

    def test_repr(self):
        t = ScanTarget("10.0.0.1", 80)
        t.service = "http"
        r = repr(t)
        assert "10.0.0.1" in r
        assert "http" in r
