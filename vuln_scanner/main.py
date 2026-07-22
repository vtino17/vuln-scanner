import sys
import argparse


def build_parser():
    parser = argparse.ArgumentParser(
        description="Vulnerability scanner for network devices and services"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run a vulnerability scan")
    scan.add_argument("target", help="IP address, hostname, or CIDR range")
    scan.add_argument("--output", "-o", default=None, help="Output file path")
    scan.add_argument("--format", "-f", choices=["json", "html", "csv", "sarif"],
                      default="json", help="Output format")
    scan.add_argument("--cve", action="store_true", help="Enable CVE correlation")
    scan.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                      default="medium", help="Minimum severity level")
    scan.add_argument("--ports", default="80,443,22,3389,8080",
                      help="Comma-separated port list")
    scan.add_argument("--rate", type=int, default=100,
                      help="Max packets per second")
    scan.add_argument("--timeout", type=int, default=5,
                      help="Connection timeout in seconds")
    scan.add_argument("--verbose", "-v", action="store_true",
                      help="Verbose output")

    plugins = sub.add_parser("plugins", help="List available scan plugins")
    plugins.add_argument("--list", action="store_true", help="List all plugins")

    sched = sub.add_parser("schedule", help="Schedule recurring scans")
    sched.add_argument("target", help="Target to scan")
    sched.add_argument("--interval", choices=["hourly", "daily", "weekly"],
                       default="daily", help="Scan interval")
    sched.add_argument("--notify", choices=["email", "slack", "webhook"],
                       help="Notification channel")

    return parser


def entry_point():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        from vuln_scanner.core.scanner import Scanner
        from vuln_scanner.core.target import TargetParser
        from vuln_scanner.reporters.factory import ReporterFactory

        targets = TargetParser.parse(args.target, args.ports)
        scanner = Scanner(rate=args.rate, timeout=args.timeout, verbose=args.verbose)

        results = []
        for target in targets:
            print(f"Scanning {target}", file=sys.stderr)
            result = scanner.scan(target)
            results.append(result)

        if args.cve:
            from vuln_scanner.plugins.cve_lookup import CVELookup
            cve = CVELookup()
            for r in results:
                cve.enrich(r, severity=args.severity)

        reporter = ReporterFactory.create(args.format)
        output = args.output or f"scan_{args.target.replace('/', '_')}.{args.format}"
        reporter.generate(results, output)

        print(f"Report saved: {output}", file=sys.stderr)

    elif args.command == "plugins":
        from vuln_scanner.core.plugin import discover_plugins
        plugins = discover_plugins()
        print(f"Available plugins ({len(plugins)}):")
        for p in plugins:
            print(f"  {p.name}: {p.description}")

    elif args.command == "schedule":
        print(f"Scheduled {args.interval} scan for {args.target}")
        if args.notify:
            print(f"Notifications via {args.notify}")

    else:
        parser.print_help()


if __name__ == "__main__":
    entry_point()
