import time
import json
import random
from locust import HttpUser, task, between, events

# Configuration
USER_APP_URL = "http://localhost:9013"
TP_URL = "http://localhost:9001"
AP_URL = "http://localhost:9002"

# Load Users
import os
try:
    # Use absolute path or relative to this file
    user_file = os.path.join(os.path.dirname(__file__), "test_users.json")
    with open(user_file, "r") as f:
        USERS = json.load(f)
except FileNotFoundError:
    print(f"{user_file} not found! Run setup_users.py first.")
    USERS = []

class RecoverUser(HttpUser):
    wait_time = between(1, 3)
    host = USER_APP_URL

    def on_start(self):
        # Disable proxy usage
        self.client.trust_env = False
        
        if not USERS:
            self.user_info = None
            return

        # Pick a random user
        user_data = random.choice(USERS)
        self.user_info = user_data["user_info"]
        self.phc = user_data.get("phc") # Not strictly needed for recover_both input, but good check

    @task
    def recover_and_reveal(self):
        if not self.user_info:
            return 

        # Call recover_both
        with self.client.post("/user/recover_both", json={
            "tp_base": TP_URL,
            "ap_base": AP_URL,
            "user": self.user_info
        }, catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"Recover Failed: {resp.status_code} {resp.text[:100]}")
            else:
                data = resp.json()
                if not data.get("success"):
                    resp.failure(f"Recover Logic Failed: {data.get('error')}")
                    return
                
                # Report Metrics
                if "perf_recover_phc_ms" in data and "perf_recover_pa_ms" in data:
                    total_recover = data["perf_recover_phc_ms"] + data["perf_recover_pa_ms"]
                    events.request.fire(
                        request_type="PHASE_1",
                        name="Recover_PHC_PA",
                        response_time=total_recover,
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                
                if "perf_tp_reveal_ms" in data:
                    events.request.fire(
                        request_type="PHASE_2",
                        name="TP_Reveal_Identity",
                        response_time=data["perf_tp_reveal_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                
                resp.success()
