import os, sys, hashlib
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from trust_provider.crypto import dl_generate_keypair, DL_P, DL_G

def sign(sk, msg):
    k = 123456789
    r = pow(DL_G, k, DL_P)
    e = int.from_bytes(hashlib.sha256(r.to_bytes(32, "big") + msg).digest(), "big") % DL_P
    s = (k + e * sk) % DL_P
    return {"e": e, "s": s}

def verify(pk, msg, sig):
    e = sig["e"]
    s = sig["s"]
    gs = pow(DL_G, s, DL_P)
    inv = pow(pk, DL_P - 2, DL_P)
    r = (gs * pow(inv, e, DL_P)) % DL_P
    e2 = int.from_bytes(hashlib.sha256(r.to_bytes(32, "big") + msg).digest(), "big") % DL_P
    return e2 == e

sk, pk = dl_generate_keypair()
msg = b"hello"
sig = sign(sk, msg)
print("verify:", verify(pk, msg, sig))