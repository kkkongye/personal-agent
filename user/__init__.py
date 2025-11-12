"""User-side lightweight SDK/CLI helpers for requesting PHC from TP.

Exposes:
- crypto: compute_af/compute_cmi helpers (deterministic, stubbed)
- models: Pydantic models for user payloads
- client: HTTP client for TP endpoints
- flow: high-level orchestration to create AF and request PHC

Note: This is a lightweight module (no server). Replace stub crypto with real
implementations and wire DID/SCID in production.
"""

from . import crypto, models, client, flow

__all__ = ["crypto", "models", "client", "flow"]
