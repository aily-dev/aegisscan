"""
Base scanner class
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    name: str
    severity: Severity
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    cwe: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class BaseScanner(ABC):
    """Base class for all scanners"""
    
    def __init__(self, http_client, engine=None):
        self.http_client = http_client
        self.engine = engine
        self.name = self.__class__.__name__
    
    @abstractmethod
    async def scan(self, url: str, **kwargs) -> List[Vulnerability]:
        """Perform the scan"""
        pass
    
    def _create_vulnerability(
        self,
        name: str,
        severity: Severity,
        url: str,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        description: str = "",
        evidence: str = "",
        recommendation: str = "",
        cwe: Optional[str] = None
    ) -> Vulnerability:
        """Helper to create vulnerability objects"""
        return Vulnerability(
            name=name,
            severity=severity,
            url=url,
            parameter=parameter,
            payload=payload,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe
        )

