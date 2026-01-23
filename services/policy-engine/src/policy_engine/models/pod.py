"""Pod models for the AVON Policy Engine."""

from typing import Optional

from pydantic import BaseModel, Field


class Pod(BaseModel):
    """Pod (group) information."""

    id: str = Field(..., description="Pod UUID")
    name: str = ""
    parent_id: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[str] = None
