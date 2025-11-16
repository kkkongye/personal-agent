import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from trust_provider.crypto import dl_generate_keypair, schnorr_sign, schnorr_verify

sk, pk = dl_generate_keypair()
msg = b"123456"
sig = schnorr_sign(sk, msg)
ok = schnorr_verify(pk, msg, sig)
print("verify:", ok)