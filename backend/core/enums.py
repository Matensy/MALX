"""Shared vocabulary used across engines, API and reports."""

from __future__ import annotations

from enum import Enum


class AnalysisStatus(str, Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    EXTRACTING = "EXTRACTING"
    ANALYZING = "ANALYZING"
    CORRELATING = "CORRELATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def terminal(self) -> bool:
        return self in (AnalysisStatus.COMPLETED, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED)


class AnalysisMode(str, Enum):
    AUTO = "auto"
    MALWARE = "malware"
    APPSEC = "appsec"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]

    @classmethod
    def parse(cls, value: str | "Severity" | None, default: "Severity" = None) -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            return default or cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}
# Contribution of a single observation to a risk dimension (before confidence/reliability).
_SEVERITY_WEIGHT = {
    Severity.INFO: 0.03, Severity.LOW: 0.12, Severity.MEDIUM: 0.30, Severity.HIGH: 0.50,
    Severity.CRITICAL: 0.70,
}


class Reliability(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def factor(self) -> float:
        return {"low": 0.6, "medium": 0.8, "high": 1.0}[self.value]

    @classmethod
    def parse(cls, value) -> "Reliability":
        try:
            return cls(str(value).lower())
        except ValueError:
            return cls.MEDIUM


class Classification(str, Enum):
    UNKNOWN = "UNKNOWN"
    BENIGN_INDICATORS = "BENIGN_INDICATORS"
    SUSPICIOUS = "SUSPICIOUS"
    HIGHLY_SUSPICIOUS = "HIGHLY_SUSPICIOUS"
    MALICIOUS_INDICATORS = "MALICIOUS_INDICATORS"


class StringClass(str, Enum):
    NORMAL = "NORMAL"
    INTERESTING = "INTERESTING"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"

    @property
    def rank(self) -> int:
        return ["NORMAL", "INTERESTING", "SUSPICIOUS", "HIGH_RISK"].index(self.value)


class AnalystState(str, Enum):
    UNKNOWN = "UNKNOWN"
    INVESTIGATING = "INVESTIGATING"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"


class FindingStrength(str, Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class IOCType(str, Enum):
    HASH = "hash"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CRYPTO_WALLET = "crypto_wallet"
    ONION = "onion"


# Evidence categories double as risk dimensions / capability groups.
CATEGORIES = {
    "structure": "File structure",
    "packing": "Packing / obfuscation",
    "execution": "Process & command execution",
    "persistence": "Persistence",
    "injection": "Process injection",
    "credential_access": "Credential access",
    "network": "Network communication",
    "anti_analysis": "Anti-analysis / evasion",
    "defense_evasion": "Defense evasion",
    "discovery": "Discovery",
    "collection": "Collection",
    "impact": "Impact (destructive / ransomware-like)",
    "privilege": "Privilege escalation",
    "document": "Document threats",
    "archive": "Archive threats",
    "mobile": "Mobile / Android",
    "signature": "Signature & trust",
    "yara": "YARA",
    "ioc": "Indicators",
    "vulnerability": "Vulnerabilities",
    "secret": "Exposed secrets",
    "code": "Source code weaknesses",
    "file_manipulation": "File manipulation",
    "info": "Informational",
}
