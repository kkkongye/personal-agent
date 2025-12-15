import time
import json
import random
import secrets
from locust import HttpUser, task, between, events

# Configuration
USER_APP_URL = "http://localhost:9013"
TP_URL = "http://localhost:9001"  # Passed to User App, client appends /v1/tp/...
AP_URL = "http://localhost:9002"  # Passed to User App, client appends /v1/ap/...

class ProtocolUser(HttpUser):
    wait_time = between(1, 3)
    # Use the User App as the primary host for the locust stats
    host = USER_APP_URL

    def on_start(self):
        # Disable proxy usage to avoid 502s in local environment
        self.client.trust_env = False
        
        # Prepare unique user data
        self.user_suffix = secrets.token_hex(4)
        self.id_number = f"11010119900101{self.user_suffix}"
        self.pii = {
            "name": f"User{self.user_suffix}", 
            "id_number": self.id_number, 
            "phone": "13800000000"
        }
        self.bi = {"pic_string": "base64_face_data_placeholder"}
        self.user_info = {
            "pii": self.pii, 
            "bi": self.bi, 
            "cdid": f"did:example:{self.user_suffix}", 
            "ecid": "g"
        }
        self.phc = None
        self.cmm = None
        self.user_sk = None
        self.user_pk = None

    @task
    def full_flow(self):
        # 1. Request PHC (Stage 1 & 2)
        # User App -> TP
        start_t = time.time()
        with self.client.post("/user/request_phc", json={
            "base_url": TP_URL,
            "user": self.user_info
        }, catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"PHC Failed: {resp.status_code} {resp.text[:100]}")
                return
            else:
                data = resp.json()
                self.phc = data.get("phc")
                if not self.phc:
                    resp.failure("No PHC in response")
                    return
                
                # Report Stage 1 & 2 Metrics
                # Stage 1: TP Verify User
                if "perf_tp_verify_user_ms" in data:
                    events.request.fire(
                        request_type="STAGE_1",
                        name="TP_Verify_User",
                        response_time=data["perf_tp_verify_user_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                # Stage 2: TP Issue PHC
                if "perf_tp_issue_ms" in data:
                    events.request.fire(
                        request_type="STAGE_2",
                        name="TP_Issue_PHC",
                        response_time=data["perf_tp_issue_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                # Stage 2: User Verify PHC
                if "perf_user_verify_phc_ms" in data:
                    events.request.fire(
                        request_type="STAGE_2",
                        name="User_Verify_PHC",
                        response_time=data["perf_user_verify_phc_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
        
        # 2. CMM Init (Stage 3)
        # User App -> AP
        with self.client.post("/user/cmm_init", json={
            "base_url": AP_URL,
            "phc": self.phc,
            "user": self.user_info
        }, catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"CMM Init Failed: {resp.status_code} {resp.text[:100]}")
                return
            else:
                data = resp.json()
                self.cmm = data.get("cmm")
                self.user_sk = data.get("sk")
                self.user_pk = data.get("pk")
                if not self.cmm:
                    resp.failure("No CMM in response")
                    return
                
                # Stage 3: AP Verify PHC
                if "perf_ap_verify_phc_ms" in data:
                    events.request.fire(
                        request_type="STAGE_3",
                        name="AP_Verify_PHC",
                        response_time=data["perf_ap_verify_phc_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )

        # 3. CMM Submit (Stage 4)
        # User App -> AP
        cmc = [
            [{"label": "text-processing"}],
            [{"label": "text"}],
            [{"label": "rag"}],
            [{"label": "local"}],
            [{"label": "text"}],
            [{"label": "blue"}],
        ]
        
        with self.client.post("/user/cmm_submit", json={
            "base_url": AP_URL,
            "cmc": cmc,
            "hid": self.id_number,
            "phc": self.phc,
            "user_sk": self.user_sk,
            "user_pk": self.user_pk
        }, catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"CMM Submit Failed: {resp.status_code} {resp.text[:100]}")
            else:
                data = resp.json()
                # Stage 4: AP Generate PA
                if "perf_ap_generate_pa_ms" in data:
                    events.request.fire(
                        request_type="STAGE_4",
                        name="AP_Generate_PA",
                        response_time=data["perf_ap_generate_pa_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                # Stage 4: User Verify PA
                if "perf_user_verify_pa_ms" in data:
                    events.request.fire(
                        request_type="STAGE_4",
                        name="User_Verify_PA",
                        response_time=data["perf_user_verify_pa_ms"],
                        response_length=0,
                        exception=None,
                        context=self.context(),
                    )
                resp.success()

