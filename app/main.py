from fastapi import FastAPI
from trust_provider.issue_phc import router as tp_router
from agent_provider.ap import router as ap_router

app = FastAPI()
app.include_router(tp_router, prefix="/v1")
app.include_router(ap_router, prefix="/v1")