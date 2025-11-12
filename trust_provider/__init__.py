"""Trust Provider (TP) minimal skeleton package.

This package provides a very small, extendable Trust Provider service that
implements the minimal endpoints referenced by the PA.md design:

- /tp/issue_phc   -> issue a Personhood Credential (PHC) JSON-LD stub
- /tp/verify_phc  -> verify a PHC signature/structure (stubbed)
- /tp/trace       -> perform identity trace given an RF (stubbed)

All cryptographic implementations here are minimal stubs intended to be
replaced by production implementations (Paillier, chameleon hash, IPFS).
"""

__all__ = ["router", "PHCService"]
