from fastapi import FastAPI
from trust_provider.issue_phc import router as tp_router
from agent_provider.ap import router as ap_router
from pic.pic_upload import router as pic_router

from app.user_app import app as user_app

app = FastAPI()
app.include_router(tp_router, prefix="/v1")
app.include_router(ap_router, prefix="/v1")
app.include_router(pic_router, prefix="/v1")

# Mount user app to handle /user requests
# app.mount("/user", user_app)
# user_app has @app.post('/user/request_phc'), so if I mount at /user, it becomes /user/user/request_phc?
# No, mount strips the prefix.
# If I mount at "/", then it might conflict or work.
# But user_app routes are defined as '/user/request_phc'.
# So if I mount at "/", it will be available at "/user/request_phc".
app.mount("/", user_app)