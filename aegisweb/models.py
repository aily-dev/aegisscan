from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
import json


Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # IP address that registered this account
    registered_ip = Column(String(64), nullable=False)
    # JSON list of domains that this user has scanned
    scanned_domains_json = Column(Text, default="[]")

    def get_id(self) -> str:  # Flask-Login compatibility
        return str(self.id)

    @property
    def scanned_domains(self) -> List[str]:
        try:
            data = json.loads(self.scanned_domains_json or "[]")
            if isinstance(data, list):
                return [str(d) for d in data]
        except Exception:
            pass
        return []

    @scanned_domains.setter
    def scanned_domains(self, value: List[str]) -> None:
        self.scanned_domains_json = json.dumps(list(dict.fromkeys(value)))


