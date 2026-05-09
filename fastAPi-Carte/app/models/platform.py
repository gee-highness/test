# app/models/platform.py
from typing import Optional
from pydantic import EmailStr
from datetime import datetime
from .base import MongoModel


class PlatformAdmin(MongoModel):
    """Platform-level super admin. Completely separate from tenant employees."""
    name: str
    email: EmailStr
    password_hash: str
    is_active: bool = True
    password_changed: bool = False   # False = must change on first login
    last_login: Optional[datetime] = None

    def to_response_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "is_active": self.is_active,
            "password_changed": self.password_changed,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
        }
