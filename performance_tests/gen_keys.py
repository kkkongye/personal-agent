import sys
import os

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_lib import generate_paillier_keypair, dl_generate_keypair
tp_paillier = generate_paillier_keypair(nbits=128)
tp_sk, tp_pk = dl_generate_keypair()
ap_sk, ap_pk = dl_generate_keypair()

print("TP_PAILLIER_PUB =", tp_paillier.public)
print("TP_PAILLIER_PRIV =", tp_paillier.private)
print(f"TP_DL_SK = {tp_sk}")
print(f"TP_DL_PK = {tp_pk}")
print(f"AP_SK = {ap_sk}")
print(f"AP_PK = {ap_pk}")
