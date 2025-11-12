"""High-level user flow to request PHC.

Two modes:
- local_issue: call TP issue function in-process (no HTTP), for tests
- remote_issue: use HTTP client to call TP service
"""
from typing import Dict, Any, Optional

from .models import UserInfo, AFResult, PHCResponse
from .crypto import compute_r_bind, compute_af, compute_cmi, sign_with_secret


def local_issue(user: UserInfo, user_secret: str = "user_secret") -> Dict[str, Any]:
    """Issue PHC by directly calling TP's function (for local tests).

    Maps AF/CMI into TP's fallback payload (af, cmi, cdid, ecid).
    Returns {af_result, phc_response}
    """
    # Lazy import to avoid hard dependency at import time
    from octopus.trust_provider.service import issue_phc
    from octopus.trust_provider.service import ASOCompleteModel

    r_bind = compute_r_bind()
    pii = user.pii.model_dump()
    bi = user.bi.model_dump()
    af = compute_af(pii, bi, r_bind)
    cmi = compute_cmi(pii)

    # Optional user signature over request (not currently verified by TP stub)
    user_sig = sign_with_secret(user_secret, {"AF": af, "PII": pii, "BI": bi})

    req = ASOCompleteModel(af=af, cmi=cmi, cdid=user.cdid, ecid=user.ecid)
    res = issue_phc(req)

    return {
        "af_result": AFResult(af=af, cmi=cmi, r_bind=r_bind).model_dump(),
        "user_sig": user_sig,
        "phc_response": res,
    }


def remote_issue(base_url: str, user: UserInfo) -> PHCResponse:
    from .client import request_phc_remote

    return request_phc_remote(base_url, user)
