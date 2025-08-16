"""Top‑level package for the IDS Isolation Forest project.

This package exposes utilities for capturing network packets, aggregating
them into flows, extracting features and training/using an Isolation
Forest model to detect anomalous network activity.

The public API surface is intentionally minimal; most users will
interact with the package via the console scripts defined in
``pyproject.toml``.
"""

from importlib.metadata import version as _version

try:
    __version__ = _version("ids-iforest")
except Exception:
    # Fallback when installed in editable mode without metadata
    __version__ = "0.0.0.dev"

__all__ = ["__version__"]
