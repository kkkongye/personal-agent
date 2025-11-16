import json
import sys, os
sys.path.insert(0, os.getcwd())
from trust_provider.phc import build_phc
from trust_provider.crypto import sign_with_secret, canonical_json
from agent_provider.ap import request_pa, APInbound, AP_PK
from user.crypto import elgamal_encrypt_bytes
from user.crypto import dl_generate_user_keypair
from user.crypto import sha256_hex

def run():
    tpm = {"Time": "t", "CDID": "cdid", "AF": "af", "ECID": "ecid"}
    apm = {"Time": "t", "CMI": "cmi"}
    aso = {"TPM": tpm, "APM": apm}
    tpid = "tpid"
    tpproof = sign_with_secret("tp_secret", {"TPM": tpm, "TPid": tpid})
    tpa = {"TPid": tpid, "TPproof": tpproof}
    apa = {"APid": "apid", "APproof": "x"}
    phc = build_phc(aso=aso, tpa=tpa, apa=apa, tp_secret="tp_secret")
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex("ID123")
    ar_plain = {"PHC": phc, "HID": hid, "TPAC": phc.get("TPA")}
    ar = elgamal_encrypt_bytes(AP_PK, ar_plain)
    out = request_pa(APInbound(ar=ar, user_pub=pk_a))
    par = out["par"]
    from trust_provider.crypto import elgamal_decrypt_bytes
    raw = elgamal_decrypt_bytes(sk_a, par)
    obj = json.loads(raw.decode())
    assert "PA" in obj and "PHC" in obj

if __name__ == "__main__":
    run()