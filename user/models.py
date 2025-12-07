"""Pydantic models for user module (PII/BI and PHC request flow)."""
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class PIIModel(BaseModel):
    name: str
    id_number: str
    id_card_number: Optional[str] = None
    email: Optional[str] = None


class BIModel(BaseModel):
    last_login_ip: Optional[str] = None
    passport_number: Optional[str] = None
    pic_string: Optional[str] = None


class UserInfo(BaseModel):
    pii: PIIModel
    bi: BIModel
    cdid: Optional[str] = Field(default="cdid:user.placeholder", description="Chained DID or user DID reference")
    ecid: Optional[str] = Field(default="g", description="Group or environment code")


class AFResult(BaseModel):
    af: str
    cmi: str
    r_bind: str


class PHCResponse(BaseModel):
    success: bool
    phc: Dict[str, Any]
    mode: Optional[str] = None
    face_verified: Optional[bool] = None
    face_check_ms: Optional[float] = None
