import json
import tempfile
import os
from vuln_scanner.reporters.json_reporter import JSONReporter


class TestJSONReporter:

    def test_generate_empty(self):
        reporter = JSONReporter()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            reporter.generate([], path)
            with open(path) as f:
                data = json.load(f)
            assert "scan_metadata" in data
            assert data["scan_metadata"]["total_targets"] == 0
            assert data["results"] == []
        finally:
            os.unlink(path)

    def test_generate_with_results(self):
        reporter = JSONReporter()
        results = [
            {"host": "10.0.0.1", "port": 80, "status": "open", "service": "http"},
            {"host": "10.0.0.1", "port": 443, "status": "open", "service": "https"},
            {"host": "10.0.0.1", "port": 22, "status": "closed", "service": None},
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            reporter.generate(results, path)
            with open(path) as f:
                data = json.load(f)
            assert data["scan_metadata"]["total_targets"] == 3
            assert data["scan_metadata"]["open_ports"] == 2
            assert len(data["results"]) == 3
        finally:
            os.unlink(path)
