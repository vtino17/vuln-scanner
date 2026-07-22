import json
import urllib.request
import urllib.error
import ssl


class CVELookup:

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.cache = {}
        self.ctx = ssl.create_default_context()

    def enrich(self, scan_result, severity="medium"):
        service = scan_result.get("service", "")
        version = scan_result.get("version", "")

        if not service:
            return scan_result

        cves = self._query_cve(service, version)
        matching = [c for c in cves if self._meets_severity(c, severity)]

        scan_result["vulnerabilities"] = matching
        scan_result["vuln_count"] = len(matching)
        scan_result["max_severity"] = self._max_severity(matching)

        return scan_result

    def _query_cve(self, service, version):
        if not service:
            return []

        keyword = service
        if version:
            keyword = f"{service} {version}"

        cache_key = keyword.lower()
        if cache_key in self.cache:
            return self.cache[cache_key]

        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        })

        url = f"{self.NVD_API}?{params}"
        req = urllib.request.Request(url)

        if self.api_key:
            req.add_header("apiKey", self.api_key)

        try:
            with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulnerabilities = data.get("vulnerabilities", [])
                results = []
                for vuln in vulnerabilities[:10]:
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    results.append({
                        "id": cve.get("id", ""),
                        "description": cve.get("descriptions", [{}])[0].get("value", ""),
                        "severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                        "score": cvss_v3.get("baseScore", 0),
                        "published": cve.get("published", ""),
                    })
                self.cache[cache_key] = results
                return results
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
            return []

    def _meets_severity(self, cve, min_severity):
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        cve_sev = severity_order.get(cve.get("severity", "").lower(), 0)
        min_sev = severity_order.get(min_severity.lower(), 2)
        return cve_sev >= min_sev

    def _max_severity(self, cves):
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        max_sev = "unknown"
        max_val = 0
        for cve in cves:
            sev = cve.get("severity", "").lower()
            val = severity_order.get(sev, 0)
            if val > max_val:
                max_val = val
                max_sev = sev
        return max_sev
