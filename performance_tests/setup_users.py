import requests
import json
import secrets
import concurrent.futures
import time

USER_APP_URL = "http://localhost:9013"
TP_URL = "http://localhost:9001"
AP_URL = "http://localhost:9002"

USERS_FILE = "test_users.json"
COUNT = 500

def create_and_register_user(idx):
    try:
        # 1. Prepare User
        user_suffix = secrets.token_hex(4)
        id_number = f"11010119900101{user_suffix}"
        pii = {
            "name": f"User{user_suffix}", 
            "id_number": id_number, 
            "phone": "13800000000"
        }
        bi = {"pic_string": "base64_face_data_placeholder"}
        user_info = {
            "pii": pii, 
            "bi": bi, 
            "cdid": f"did:example:{user_suffix}", 
            "ecid": "g"
        }

        # 2. Request PHC
        resp = requests.post(f"{USER_APP_URL}/user/request_phc", json={
            "base_url": TP_URL,
            "user": user_info
        }, timeout=30)
        if resp.status_code != 200:
            print(f"User {idx}: PHC Failed {resp.status_code}")
            return None
        phc = resp.json().get("phc")
        if not phc:
            print(f"User {idx}: No PHC")
            return None

        # 3. CMM Init
        resp2 = requests.post(f"{USER_APP_URL}/user/cmm_init", json={
            "base_url": AP_URL,
            "phc": phc,
            "user": user_info
        }, timeout=30)
        if resp2.status_code != 200:
            print(f"User {idx}: CMM Init Failed {resp2.status_code}")
            return None
        d = resp2.json()
        user_sk = d.get("sk")
        user_pk = d.get("pk")

        # 4. CMM Submit (Issue PA)
        cmc = [[{"label": "text-processing"}]]
        resp3 = requests.post(f"{USER_APP_URL}/user/cmm_submit", json={
            "base_url": AP_URL,
            "cmc": cmc,
            "hid": id_number,
            "phc": phc,
            "user_sk": user_sk,
            "user_pk": user_pk
        }, timeout=30)
        if resp3.status_code != 200:
            print(f"User {idx}: CMM Submit Failed {resp3.status_code}")
            return None
        
        print(f"User {idx}: Success")
        return {
            "user_info": user_info,
            "phc": phc, # Optional, but good for ref
            "pa_issued": True
        }
    except Exception as e:
        print(f"User {idx}: Exception {e}")
        return None

def main():
    print(f"Generating {COUNT} users...")
    valid_users = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(create_and_register_user, i) for i in range(COUNT)]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                valid_users.append(res)
    
    print(f"Successfully registered {len(valid_users)} users.")
    with open(USERS_FILE, "w") as f:
        json.dump(valid_users, f, indent=2)

if __name__ == "__main__":
    main()
