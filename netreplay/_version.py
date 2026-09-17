"""Single source of truth for the NetReplay version.

``pyproject.toml`` reads this attribute at build time
(``[tool.setuptools.dynamic] version = {attr = "netreplay._version.__version__"}``)
and the package/API read it at import time, so the version is defined exactly
once.
"""

__version__ = "1.0.0"
