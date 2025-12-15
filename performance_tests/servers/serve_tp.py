import sys
import os

# Add project root to sys.path to allow imports from trust_provider, agent_provider, etc.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi import FastAPI
from trust_provider.issue_phc import router
import os

os.environ["ALLOW_TEST_USERS"] = "1"

app = FastAPI()
app.include_router(router, prefix="/v1")
