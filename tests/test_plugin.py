from vuln_scanner.core.plugin import BasePlugin, discover_plugins


class TestBasePlugin:

    def test_base_cannot_run(self):
        plugin = BasePlugin()
        try:
            plugin.run("test")
            assert False
        except NotImplementedError:
            assert True


class TestPluginDiscovery:

    def test_discover_returns_list(self):
        plugins = discover_plugins()
        assert isinstance(plugins, list)
