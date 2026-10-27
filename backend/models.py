from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IdentityStatus(str, Enum):
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    SUSPENDED = "SUSPENDED"

class AccessDecision(str, Enum):
    GRANTED = "GRANTED"
    CHALLENGED = "CHALLENGED"
    BLOCKED = "BLOCKED"

class Identity(BaseModel):
    id: str
    name: str
    email: str
    role: str
    department: str
    status: IdentityStatus
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    mfa_enabled: bool
    last_login: datetime
    last_ip: str
    last_location: str
    coordinates: List[float] # [lat, lon]
    device: str
    privilege_tier: str # Standard, Elevated, SuperAdmin
    active_sessions: int
    compromised_credentials_detected: bool = False

class AccessLog(BaseModel):
    id: str
    timestamp: datetime
    user_id: str
    user_name: str
    ip_address: str
    location: str
    coordinates: List[float]
    device: str
    decision: AccessDecision
    risk_score: int
    risk_factors: List[str]
    velocity_kmh: Optional[float] = None

class SecurityPolicy(BaseModel):
    id: str
    name: str
    description: str
    category: str # "Authentication", "Geo-Fencing", "Risk Threshold", "Device Security"
    enabled: bool
    risk_threshold: Optional[int] = None
    action: str # "Block", "Step-Up MFA", "Quarantine Identity", "Alert Only"

class Incident(BaseModel):
    id: str
    title: str
    severity: RiskLevel
    timestamp: datetime
    user_id: str
    user_name: str
    mitre_attack_id: str
    mitre_technique: str
    status: str # "ACTIVE", "CONTAINED", "RESOLVED"
    description: str
    ip_address: str
    recommended_action: str

class PasswordAuditRequest(BaseModel):
    password: str

class PasswordAuditResponse(BaseModel):
    entropy_bits: float
    strength: str # "Very Weak", "Weak", "Moderate", "Strong", "Military-Grade"
    score: int # 0 to 100
    has_uppercase: bool
    has_lowercase: bool
    has_numbers: bool
    has_special: bool
    length: int
    estimated_crack_time: str
    breach_count: int
    is_compromised: bool
    feedback: List[str]

class DomainBreachScanRequest(BaseModel):
    query: str # email or domain

class DomainBreachRecord(BaseModel):
    source: str
    date_leaked: str
    compromised_data: List[str]
    severity: RiskLevel

class MfaGenerateResponse(BaseModel):
    secret: str
    uri: str
    current_token: str
    time_remaining: int

class MfaVerifyRequest(BaseModel):
    secret: str
    token: str

class MfaVerifyResponse(BaseModel):
    valid: bool
    message: str

class SimulateAccessRequest(BaseModel):
    user_id: str
    scenario: str # "normal", "impossible_travel", "brute_force", "anomalous_device"
