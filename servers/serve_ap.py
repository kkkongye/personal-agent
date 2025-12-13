import sys
import os

# Add project root to sys.path to allow imports from trust_provider, agent_provider, etc.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from agent_provider.ap import router

app = FastAPI()
app.include_router(router, prefix="/v1")