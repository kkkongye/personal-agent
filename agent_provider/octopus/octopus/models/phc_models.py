from typing import Any
from pydantic import BaseModel, Field


class AnchoringFactor(BaseModel):
    af_id: str
    user_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    chain_head: str | None = None


class HashChainEntry(BaseModel):
    index: int
    item_name: str
    item_params: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


class HashChain(BaseModel):
    entries: list[HashChainEntry] = Field(default_factory=list)
    head: str


class PersonalAgentConfig(BaseModel):
    selections: dict[str, list[str]] = Field(default_factory=dict)


class PHC(BaseModel):
    scid: dict[str, Any] = Field(default_factory=dict)
    did: str | None = None
    agent_description: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = None


class PAResponse(BaseModel):
    updated_phc: PHC
    pa_manifest: dict[str, Any]