import time
from user.models import PIIModel, BIModel, UserInfo
from user.apply_agent import request_phc_remote, request_pa_remote

def run(base_url: str):
    user = UserInfo(
        pii=PIIModel(name="Alice", id_number="ID123", id_card_number="IDCARD123456", email="alice@example.com"),
        bi=BIModel(last_login_ip="127.0.0.1", passport_number="P123456789"),
    )
    phc_resp = request_phc_remote(base_url, user)
    phc = phc_resp.phc
    out = request_pa_remote(base_url, phc, user)
    return {"phc": phc, "pa": out.get("PA"), "r_bind2": out.get("r_bind2")}

if __name__ == "__main__":
    print(run("http://127.0.0.1:8000"))