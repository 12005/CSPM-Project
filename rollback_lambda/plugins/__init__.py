"""
Plugin auto-discovery system.
Each plugin registers its supported rules via SUPPORTED_RULES.
The orchestrator calls get_plugin(rule_id) to find the right handler.
"""
import importlib
import os

_REGISTRY = {}  # rule_id -> module

def _discover():
    plugins_dir = os.path.dirname(__file__)
    for fname in os.listdir(plugins_dir):
        if fname.endswith(".py") and fname != "__init__.py":
            mod_name = f"plugins.{fname[:-3]}"
            try:
                mod = importlib.import_module(mod_name)
                for rule in getattr(mod, "SUPPORTED_RULES", []):
                    _REGISTRY[rule] = mod
            except Exception as e:
                print(f"Failed to load plugin {fname}: {e}")

def get_plugin(rule_id):
    if not _REGISTRY:
        _discover()
    return _REGISTRY.get(rule_id)

def list_supported_rules():
    if not _REGISTRY:
        _discover()
    return list(_REGISTRY.keys())
