import time, os, secrets, json, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from crypto_lib import DL_P, inv_mod

def _split_secret(secret: int, n: int, t: int) -> list[tuple[int, int]]:
    coeffs = [secret] + [secrets.randbelow(DL_P - 1) + 1 for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        xp = 1
        for c in coeffs:
            y = (y + c * xp) % DL_P
            xp = (xp * x) % DL_P
        shares.append((x, y))
    return shares

def _reconstruct(shares: list[tuple[int, int]]) -> int:
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj % DL_P)) % DL_P
            den = (den * (xi - xj) % DL_P) % DL_P
        lam = (num * inv_mod(den, DL_P)) % DL_P
        s = (s + yi * lam) % DL_P
    return s

def run(loops: int, n: int, t: int) -> dict:
    secret = int.from_bytes(os.urandom(32), "big") % DL_P
    s1 = time.perf_counter()
    for _ in range(loops):
        _ = _split_secret(secret, n, t)
    t_share = (time.perf_counter() - s1) * 1000.0 / loops
    shares = _split_secret(secret, n, t)
    s2 = time.perf_counter()
    for _ in range(loops):
        _ = _reconstruct(shares[:t])
    t_rec = (time.perf_counter() - s2) * 1000.0 / loops
    return {"Tsg_ms": t_share, "Tsg_rec_ms": t_rec}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--loops", type=int, default=100)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--t", type=int, default=3)
    args = ap.parse_args()
    out = {"loops": args.loops, "n": args.n, "t": args.t, "results": run(args.loops, args.n, args.t)}
    print(json.dumps(out))
