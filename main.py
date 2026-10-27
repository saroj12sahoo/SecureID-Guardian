import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import List, Optional, Dict, Any

from backend.models import (
    Identity, AccessLog, SecurityPolicy, Incident,
    PasswordAuditRequest, PasswordAuditResponse,
    DomainBreachScanRequest, DomainBreachRecord,
    MfaGenerateResponse, MfaVerifyRequest, MfaVerifyResponse,
    SimulateAccessRequest
)
from backend.crypto_security import TOTPGenerator, PasswordAuditor
from backend.policy_engine import security_state
from backend.sample_data import SAMPLE_BREACH_RECORDS

app = FastAPI(
    title="SecureID Guardian API",
    description="Enterprise Zero-Trust Cybersecurity & Identity Protection Platform",
    version="1.0.0"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dashboard & Metrics Endpoints ---
@app.get("/api/dashboard/stats")
def get_dashboard_stats() -> Dict[str, Any]:
    identities = security_state.get_identities()
    active_incidents = [i for i in security_state.incidents.values() if i.status == "ACTIVE"]
    quarantined = [u for u in identities if u.status == "QUARANTINED"]
    high_risk = [u for u in identities if u.risk_score >= 60]
    
    # Calculate security health posture (100 - weighted risk average)
    avg_risk = sum(u.risk_score for u in identities) / max(1, len(identities))
    posture_score = max(10, min(100, int(100 - avg_risk)))
    
    # Active policies
    enabled_policies = [p for p in security_state.policies.values() if p.enabled]

    return {
        "security_posture_score": posture_score,
        "threat_level": "ELEVATED" if len(active_incidents) > 0 else "NORMAL",
        "total_identities": len(identities),
        "quarantined_count": len(quarantined),
        "high_risk_count": len(high_risk),
        "active_incidents_count": len(active_incidents),
        "active_policies_count": len(enabled_policies),
        "total_policies_count": len(security_state.policies),
        "total_access_logs": len(security_state.access_logs)
    }

# --- Identity Endpoints ---
@app.get("/api/identities", response_model=List[Identity])
def list_identities(
    department: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None
) -> List[Identity]:
    identities = security_state.get_identities()
    if department:
        identities = [u for u in identities if u.department.lower() == department.lower()]
    if risk_level:
        identities = [u for u in identities if u.risk_level.value.lower() == risk_level.lower()]
    if search:
        s = search.lower()
        identities = [
            u for u in identities 
            if s in u.name.lower() or s in u.email.lower() or s in u.role.lower()
        ]
    return identities

@app.get("/api/identities/{user_id}", response_model=Identity)
def get_identity(user_id: str) -> Identity:
    identity = security_state.get_identity(user_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity

@app.post("/api/identities/{user_id}/quarantine", response_model=Identity)
def quarantine_identity(user_id: str) -> Identity:
    identity = security_state.quarantine_identity(user_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity

@app.post("/api/identities/{user_id}/unquarantine", response_model=Identity)
def unquarantine_identity(user_id: str) -> Identity:
    identity = security_state.unquarantine_identity(user_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity

@app.post("/api/identities/{user_id}/step-up", response_model=Identity)
def step_up_identity(user_id: str) -> Identity:
    identity = security_state.step_up_mfa_identity(user_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity

# --- Access Logs & Telemetry Endpoints ---
@app.get("/api/access-logs", response_model=List[AccessLog])
def list_access_logs(limit: int = 50) -> List[AccessLog]:
    return security_state.access_logs[:limit]

@app.post("/api/access-logs/simulate", response_model=AccessLog)
def simulate_access_event(payload: SimulateAccessRequest) -> AccessLog:
    try:
        log = security_state.simulate_event(payload.user_id, payload.scenario)
        return log
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# --- Password & Breach Auditor Endpoints ---
@app.post("/api/audit/password", response_model=PasswordAuditResponse)
def audit_password(payload: PasswordAuditRequest) -> PasswordAuditResponse:
    res = PasswordAuditor.audit(payload.password)
    return PasswordAuditResponse(**res)

@app.post("/api/audit/domain-breach", response_model=List[DomainBreachRecord])
def audit_domain_breach(payload: DomainBreachScanRequest) -> List[DomainBreachRecord]:
    q = payload.query.strip().lower()
    matches = []
    for target, records in SAMPLE_BREACH_RECORDS.items():
        if target in q or q in target:
            matches.extend(records)
    
    # If no exact match, simulate standard dark web search result for realistic engagement
    if not matches:
        if "@" in q:
            domain = q.split("@")[-1]
            if domain in SAMPLE_BREACH_RECORDS:
                matches.extend(SAMPLE_BREACH_RECORDS[domain])
    return matches

# --- RFC-6238 MFA Authenticator Endpoints ---
@app.get("/api/mfa/generate", response_model=MfaGenerateResponse)
def generate_mfa(account: str = "security.admin@cybercorp.internal") -> MfaGenerateResponse:
    secret = TOTPGenerator.generate_secret()
    token, time_remaining = TOTPGenerator.get_totp_token(secret)
    uri = f"otpauth://totp/SecureID-Guardian:{account}?secret={secret}&issuer=SecureIDGuardian&algorithm=SHA1&digits=6&period=30"
    return MfaGenerateResponse(
        secret=secret,
        uri=uri,
        current_token=token,
        time_remaining=time_remaining
    )

@app.post("/api/mfa/verify", response_model=MfaVerifyResponse)
def verify_mfa(payload: MfaVerifyRequest) -> MfaVerifyResponse:
    is_valid = TOTPGenerator.verify_token(payload.secret, payload.token)
    msg = "Cryptographic OTP Token Verified Successfully (Zero-Trust Assertion Accepted)" if is_valid else "Token Mismatch or Expired Time Window"
    return MfaVerifyResponse(valid=is_valid, message=msg)

# --- Policies Endpoints ---
@app.get("/api/policies", response_model=List[SecurityPolicy])
def list_policies() -> List[SecurityPolicy]:
    return list(security_state.policies.values())

@app.post("/api/policies/{policy_id}/toggle", response_model=SecurityPolicy)
def toggle_policy(policy_id: str, enabled: bool = Query(...)) -> SecurityPolicy:
    pol = security_state.toggle_policy(policy_id, enabled)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    return pol

# --- Incidents & Threat Defense Endpoints ---
@app.get("/api/incidents", response_model=List[Incident])
def list_incidents() -> List[Incident]:
    return list(security_state.incidents.values())

@app.post("/api/incidents/{incident_id}/resolve", response_model=Incident)
def resolve_incident(incident_id: str) -> Incident:
    inc = security_state.resolve_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

# --- Serve Static Frontend Files ---
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "SecureID Guardian API is running. Build frontend/index.html to view UI."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
