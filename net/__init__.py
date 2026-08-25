"""Networking layer: onion framing, DTN mesh, and dark pool simulations.

Everything is simulated with deterministic seeds — no real sockets, no hardware.
"""

from . import dtn, darkpool, sphinx  # noqa: F401  (import order: sphinx deps first)

__all__ = ["dtn", "sphinx", "darkpool"]