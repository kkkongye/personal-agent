from user.models import PIIModel, BIModel, UserInfo
from user.crypto import compute_cmi, compute_r_bind, sha256_hex, canonical_json
from app.main import app
import httpx
import asyncio

async def run_async():
    user = UserInfo(
        pii=PIIModel(name="Alice", id_number="ID123", id_card_number="IDCARD123456", email="alice@example.com"),
        bi=BIModel(last_login_ip="127.0.0.1", passport_number="P123456789"),
    )
    r_bind = compute_r_bind()
    af = sha256_hex(canonical_json({"pii": user.pii.model_dump(), "bi": user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
    cmi = compute_cmi(user.pii.model_dump())
    payload = {"af": af, "cmi": cmi, "cdid": user.cdid, "ecid": user.ecid}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        phc_resp = await client.post("/v1/tp/issue_phc", json=payload, timeout=10.0)
        phc = phc_resp.json()["phc"]
        pub = (await client.get("/v1/ap/public_keys", timeout=10.0)).json()
        ap_dlog_pk = pub["ap_dlog_pk"]
        from user.crypto import dl_generate_user_keypair, elgamal_encrypt_bytes
        sk_a, pk_a = dl_generate_user_keypair()
        hid = sha256_hex(user.pii.id_number)
        tpac = phc.get("TPA")
        ar_plain = {"PHC": phc, "HID": hid, "TPAC": tpac}
        ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
        out = (await client.post("/v1/ap/request_pa", json={"ar": ar, "user_pub": pk_a}, timeout=10.0)).json()
        from trust_provider.crypto import elgamal_decrypt_bytes
        raw = elgamal_decrypt_bytes(sk_a, out["par"]).decode()
        import json
        obj = json.loads(raw)
        return {"phc": phc, "pa": obj.get("PA")}

def run():
    return asyncio.run(run_async())

if __name__ == "__main__":
    print(run())