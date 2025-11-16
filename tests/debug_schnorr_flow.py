import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from trust_provider.crypto import dl_generate_keypair, schnorr_verify, DL_P, DL_G
import inspect
from user.crypto import schnorr_sign

sk, pk = dl_generate_keypair()
msg = b"hello"
sig = schnorr_sign(sk, msg)
ok = schnorr_verify(pk, msg, sig)
print("pk", pk)
print("sig", sig)
print("verify location:", inspect.getsourcefile(schnorr_verify))
lhs = pow(DL_G, sig['s'], DL_P)
rhs = (sig['r'] * pow(pk, sig['e'], DL_P)) % DL_P
print("lhs==rhs:", lhs == rhs)
import hashlib
e2 = int.from_bytes(hashlib.sha256(int(sig['r']).to_bytes(32,'big') + msg).digest(), 'big') % (DL_P-1)
print("e match:", e2 == sig['e'])
print("verify flow:", ok)