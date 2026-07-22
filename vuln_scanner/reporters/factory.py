from vuln_scanner.reporters.json_reporter import JSONReporter


class ReporterFactory:

    _reporters = {
        "json": JSONReporter,
    }

    @classmethod
    def register(cls, name, reporter_class):
        cls._reporters[name] = reporter_class

    @classmethod
    def create(cls, format_name):
        reporter_class = cls._reporters.get(format_name)
        if not reporter_class:
            reporter_class = JSONReporter
        return reporter_class()
