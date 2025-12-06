import time, os, json, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def run(loops: int, size: int) -> dict:
    msg = os.urandom(size)
    try:
        curve = ec.SECP256K1()
    except Exception:
        curve = ec.SECP256R1()
    sk = ec.generate_private_key(curve)
    pk = sk.public_key()
    s1 = time.perf_counter()
    for _ in range(loops):
        _ = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
    t_sig = (time.perf_counter() - s1) * 1000.0 / loops
    sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
    s2 = time.perf_counter()
    for _ in range(loops):
        pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    t_ver = (time.perf_counter() - s2) * 1000.0 / loops
    return {"Tsig1_ms": t_sig, "Tver1_ms": t_ver}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--loops", type=int, default=100)
    ap.add_argument("--size", type=int, default=1024)
    args = ap.parse_args()
    out = {"loops": args.loops, "size": args.size, "results": run(args.loops, args.size)}
    print(json.dumps(out))
