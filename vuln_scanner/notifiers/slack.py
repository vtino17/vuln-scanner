import json
import urllib.request


class SlackNotifier:

    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, message, results=None):
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": message}
            }
        ]

        if results:
            open_count = sum(1 for r in results if r.get("status") == "open")
            vuln_count = sum(1 for r in results if r.get("vuln_count", 0) > 0)
            fields = [
                {"type": "mrkdwn", "text": f"*Targets:* {len(results)}"},
                {"type": "mrkdwn", "text": f"*Open Ports:* {open_count}"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities:* {vuln_count}"},
            ]
            blocks.append({"type": "section", "fields": fields})

        payload = json.dumps({"blocks": blocks}).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"Slack notification failed: {e}")
