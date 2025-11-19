from typing import Tuple
from . import generate_paillier_keypair, dl_generate_keypair

TP_PAILLIER = generate_paillier_keypair()
TP_DL_SK, TP_DL_PK = dl_generate_keypair()
AP_SK, AP_PK = dl_generate_keypair()