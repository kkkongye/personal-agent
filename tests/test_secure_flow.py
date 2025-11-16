import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from trust_provider.issue_phc import get_public_keys, issue_phc_secure, SecureInbound
from trust_provider.crypto import ipfs_get
from user.crypto import dl_generate_user_keypair, schnorr_sign, elgamal_encrypt_bytes, compute_af_dl
from user.models import PIIModel, BIModel, UserInfo


def run_once():
    keys = get_public_keys()
    tp_pk = keys["tp_dlog_pk"]
    ap_pk = keys["ap_dlog_pk"]

    sk_a, pk_a = dl_generate_user_keypair()
    pii = PIIModel(name="Alice", id_number="ID123").model_dump()
    bi = BIModel(login_count=1).model_dump()
    r_bind = 123456

    af_val = compute_af_dl(pii["id_number"], ap_pk, tp_pk, hex(r_bind)[2:])
    pt = {
        "AF": af_val,
        "ID": pii["id_number"],
        "BI": bi,
        "PII": pii,
        "pk_ap": ap_pk,
        "r_bind": r_bind,
        "timestamp": 0,
    }
    cr = elgamal_encrypt_bytes(tp_pk, pt)
    sig = schnorr_sign(sk_a, str(r_bind).encode())
    req = SecureInbound(cr=cr, user_pub=pk_a, sig=sig)
    resp = issue_phc_secure(req)
    cid = resp["phc"]["CID"]
    sec = ipfs_get(cid)
    resp["ipfs_echo_match"] = (sec == resp["phc"]["Secinfo"])
    return resp


if __name__ == "__main__":
    r = run_once()
    print(json.dumps(r, ensure_ascii=False, indent=2))