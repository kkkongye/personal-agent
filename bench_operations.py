import time
import json
import secrets
from crypto_lib import (
    schnorr_sign, schnorr_verify, 
    dl_generate_keypair, canonical_json,
    generate_paillier_keypair, paillier_encrypt,
    elgamal_encrypt_bytes, elgamal_decrypt_bytes,
    compute_af_formal, DL_P, DL_Q
)
from crypto_lib.keys import TP_PAILLIER, TP_DL_PK, TP_DL_SK, AP_PK, AP_SK

def bench_schnorr_verify():
    # Setup
    msg = b"test_message_for_verification"
    sk, pk = dl_generate_keypair()
    sig = schnorr_sign(sk, msg)
    
    # Bench
    loops = 1000
    t0 = time.perf_counter()
    for _ in range(loops):
        schnorr_verify(pk, msg, sig)
    t1 = time.perf_counter()
    
    avg_ms = (t1 - t0) * 1000 / loops
    print(f"Schnorr Verify (User/AP Verify PHC): {avg_ms:.4f} ms per op")

def bench_ap_generate_logic():
    # Setup
    # Simulate AP Generate logic: decrypt, sign, compute AF, encrypt
    # 1. Decrypt
    payload_ar = elgamal_encrypt_bytes(AP_PK, b'{"PHC":{}, "HID":"123"}')
    
    # 2. Sign
    apm = {"CMI": "123", "Time": "now"}
    apid = str(AP_PK)
    
    # 3. Encrypt
    user_sk, user_pk = dl_generate_keypair()
    
    # 4. AF
    id_str = "123"
    cmi = 123
    crf = 456
    rb = 789
    
    loops = 1000
    t0 = time.perf_counter()
    for _ in range(loops):
        # Decrypt
        _ = elgamal_decrypt_bytes(AP_SK, payload_ar)
        
        # Sign
        _ = schnorr_sign(AP_SK, canonical_json({"APM": apm, "APid": apid}).encode())
        
        # Compute AF
        _ = compute_af_formal(id_str, AP_PK, TP_DL_PK, cmi, crf, rb)
        
        # Encrypt (mock return)
        _ = elgamal_encrypt_bytes(user_pk, b"response_data")
        
    t1 = time.perf_counter()
    avg_ms = (t1 - t0) * 1000 / loops
    print(f"AP Generate Logic (Full Flow): {avg_ms:.4f} ms per op")

def bench_tp_issue_logic():
    # Setup
    # TP Issue logic involves Paillier Encrypt
    id_hash = int(secrets.randbelow(1000000))
    
    loops = 100
    t0 = time.perf_counter()
    for _ in range(loops):
        # Paillier Encrypt
        _ = paillier_encrypt(TP_PAILLIER.public, id_hash)
    t1 = time.perf_counter()
    
    avg_ms = (t1 - t0) * 1000 / loops
    print(f"TP Issue Logic (Paillier Encrypt Only): {avg_ms:.4f} ms per op")

if __name__ == "__main__":
    print("--- Micro-Benchmark Results ---")
    bench_schnorr_verify()
    bench_ap_generate_logic()
    bench_tp_issue_logic()
