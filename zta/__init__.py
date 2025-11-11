"""
Legacy ZTA package exports with lazy importing to avoid heavyweight dependencies
during module discovery. The adaptive implementation lives under ``zta_new``.
"""

from importlib import import_module

__all__ = ["ZTANode", "ZTAPolicy", "ZTATask", "ZTALink", "ZTAEnv", "ZTAScenario"]

_MODULE_LOOKUP = {
    "ZTANode": ".zta_node",
    "ZTAPolicy": ".zta_policy",
    "ZTATask": ".task",
    "ZTALink": ".link",
    "ZTAEnv": ".env",
    "ZTAScenario": ".scenario",
}


def __getattr__(name):
    if name in _MODULE_LOOKUP:
        module = import_module(_MODULE_LOOKUP[name], __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__} has no attribute {name!r}")
