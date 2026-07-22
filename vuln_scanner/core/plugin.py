import pkgutil
import importlib


class BasePlugin:

    name = "base"
    description = "Base plugin class"

    def run(self, target):
        raise NotImplementedError


def discover_plugins():
    plugins = []
    try:
        from vuln_scanner import plugins as plugin_pkg
        for importer, modname, ispkg in pkgutil.iter_modules(plugin_pkg.__path__):
            if modname == "__init__":
                continue
            module = importlib.import_module(f"vuln_scanner.plugins.{modname}")
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, BasePlugin) and cls != BasePlugin:
                    plugins.append(cls())
    except Exception:
        pass
    return plugins
