import json
from datetime import datetime
from vuln_scanner.reporters.base import BaseReporter


class JSONReporter(BaseReporter):

    def generate(self, results, output_path):
        report = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "tool": "vuln-scanner",
                "version": "1.0.0",
                "total_targets": len(results),
                "open_ports": sum(1 for r in results if r.get("status") == "open"),
                "vulnerable": sum(1 for r in results if r.get("vuln_count", 0) > 0),
            },
            "results": results,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
