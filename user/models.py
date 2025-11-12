"""Pydantic models for user module (PII/BI and PHC request flow)."""
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class PIIModel(BaseModel):
    name: str
    id_number: str
    email: Optional[str] = None


class BIModel(BaseModel):
    # Behavior / activity indicators (stubbed)
    login_count: int = 0
    last_login_ip: Optional[str] = None
    reputation_score: float = 0.0


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
