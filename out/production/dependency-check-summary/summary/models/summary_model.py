from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel


class Overview(BaseModel):
    description: str = "Vulnerabilities overview"
    low: Optional[int]
    medium: Optional[int]
    high: Optional[int]
    critical: Optional[int]


class Criticality(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Vulnerability(BaseModel):
    name: str
    software: str
    severity: Severity
    description: str


class Report(BaseModel):
    package: str
    alerts: int
    highest: Severity
    vulnerabilities: List[Vulnerability]


class Summary(BaseModel):
    overview: Overview
    report: List[Report]
