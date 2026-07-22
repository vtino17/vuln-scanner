from vuln_scanner.notifiers.slack import SlackNotifier


class TestSlackNotifier:

    def test_initialization(self):
        notifier = SlackNotifier("https://hooks.slack.com/test")
        assert notifier.webhook_url == "https://hooks.slack.com/test"

    def test_send_handles_errors(self):
        notifier = SlackNotifier("https://hooks.slack.com/invalid")
        notifier.send("test", [{"status": "open"}])
