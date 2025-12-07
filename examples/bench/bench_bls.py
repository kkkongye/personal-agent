import time, os, json, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from py_ecc.bls import G2ProofOfPossession as bls

def run(loops: int, size: int) -> dict:
    msg = os.urandom(size)
    sk = bls.KeyGen(os.urandom(32))
    pk = bls.SkToPk(sk)
    s1 = time.perf_counter()
    for _ in range(loops):
        _ = bls.Sign(sk, msg)
    t_sig = (time.perf_counter() - s1) * 1000.0 / loops
    sig = bls.Sign(sk, msg)
    s2 = time.perf_counter()
    for _ in range(loops):
        _ = bls.Verify(pk, msg, sig)
    t_ver = (time.perf_counter() - s2) * 1000.0 / loops
    return {"TBLS_ms": t_sig, "TBLS_ver_ms": t_ver}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--loops", type=int, default=100)
    ap.add_argument("--size", type=int, default=1024)
    args = ap.parse_args()
    out = {"loops": args.loops, "size": args.size, "results": run(args.loops, args.size)}
    print(json.dumps(out))
