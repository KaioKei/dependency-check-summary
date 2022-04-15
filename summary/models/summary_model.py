from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class Overview(BaseModel):
    description: str = "Vulnerabilities overview"
    total: Optional[int] = 0
    low: Optional[int] = 0
    medium: Optional[int] = 0
    high: Optional[int] = 0
    critical: Optional[int] = 0
    uncategorized: Optional[int] = 0

    def __str__(self):
        return f"vulnerabilities: {self.total} (critical: {self.critical}, high: {self.high}, " \
               f"medium: {self.medium}, low: {self.low}, uncategorized: {self.uncategorized})"


class Criticality(int, Enum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    def __str__(self):
        return self.value


class Vulnerability(BaseModel):
    name: str
    software: str
    severity: Severity
    description: str


class Report(BaseModel):
    source: str
    alerts: int
    highest: Severity
    vulnerabilities: List[Vulnerability]


class Summary(BaseModel):
    overview: Overview
    reports: List[Report]
