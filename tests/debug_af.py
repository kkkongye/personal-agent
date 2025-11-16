import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from trust_provider.crypto import compute_af, DL_P
from user.crypto import compute_af_dl

idv = "ID123"
pk_ap = 1234567
pk_tp = 7654321
r_bind = 999
a = compute_af(idv, pk_ap, pk_tp, r_bind)
b = compute_af_dl(idv, pk_ap, pk_tp, hex(r_bind)[2:])
print("af match:", a == b, a, b, DL_P)