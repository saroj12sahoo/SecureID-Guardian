from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict
from backend.models import (
    Identity, SecurityPolicy, AccessLog, AccessDecision, RiskLevel, Incident, IdentityStatus
)
from backend.sample_data import SAMPLE_IDENTITIES, SAMPLE_POLICIES, SAMPLE_ACCESS_LOGS, SAMPLE_INCIDENTS
from backend.risk_engine import IdentityRiskEngine

class SecurityStateManager:
    """Manages mutable in-memory state of the SecureID Guardian platform."""

    def __init__(self):
        self.identities: Dict[str, Identity] = {u.id: u.model_copy(deep=True) for u in SAMPLE_IDENTITIES}
        self.policies: Dict[str, SecurityPolicy] = {p.id: p.model_copy(deep=True) for p in SAMPLE_POLICIES}
        self.access_logs: List[AccessLog] = [l.model_copy(deep=True) for l in SAMPLE_ACCESS_LOGS]
        self.incidents: Dict[str, Incident] = {i.id: i.model_copy(deep=True) for i in SAMPLE_INCIDENTS}

    def get_identities(self) -> List[Identity]:
        return list(self.identities.values())

    def get_identity(self, user_id: str) -> Optional[Identity]:
        return self.identities.get(user_id)

    def quarantine_identity(self, user_id: str) -> Optional[Identity]:
        if user_id in self.identities:
            identity = self.identities[user_id]
            identity.status = IdentityStatus.QUARANTINED
            identity.risk_score = 100
            identity.risk_level = RiskLevel.CRITICAL
            identity.active_sessions = 0

            # Generate Incident if not exists
            inc_id = f"inc-{len(self.incidents) + 701}"
            new_incident = Incident(
                id=inc_id,
                title=f"Manual SOC Containment: {identity.name}",
                severity=RiskLevel.CRITICAL,
                timestamp=datetime.now(timezone.utc),
                user_id=identity.id,
                user_name=identity.name,
                mitre_attack_id="T1531",
                mitre_technique="Account Access Removal (Containment)",
                status="CONTAINED",
                description=f"Identity {identity.name} ({identity.email}) was proactively quarantined by Security Operations to prevent lateral movement.",
                ip_address=identity.last_ip,
                recommended_action="Execute forensic credential rotation before re-enabling access."
            )
            self.incidents[inc_id] = new_incident
            return identity
        return None

    def unquarantine_identity(self, user_id: str) -> Optional[Identity]:
        if user_id in self.identities:
            identity = self.identities[user_id]
            identity.status = IdentityStatus.ACTIVE
            identity.risk_score = 15
            identity.risk_level = RiskLevel.LOW
            identity.active_sessions = 1
            identity.compromised_credentials_detected = False
            return identity
        return None

    def step_up_mfa_identity(self, user_id: str) -> Optional[Identity]:
        if user_id in self.identities:
            identity = self.identities[user_id]
            identity.status = IdentityStatus.STEP_UP_REQUIRED
            identity.risk_score = max(identity.risk_score, 55)
            identity.risk_level = RiskLevel.HIGH if identity.risk_score >= 60 else RiskLevel.MODERATE
            return identity
        return None

    def toggle_policy(self, policy_id: str, enabled: bool) -> Optional[SecurityPolicy]:
        if policy_id in self.policies:
            self.policies[policy_id].enabled = enabled
            return self.policies[policy_id]
        return None

    def resolve_incident(self, incident_id: str) -> Optional[Incident]:
        if incident_id in self.incidents:
            self.incidents[incident_id].status = "RESOLVED"
            return self.incidents[incident_id]
        return None

    def add_access_log(self, log: AccessLog):
        self.access_logs.insert(0, log)
        if len(self.access_logs) > 100:
            self.access_logs.pop()

    def simulate_event(self, user_id: str, scenario: str) -> AccessLog:
        """Simulate realistic live cyber event and evaluate against Zero-Trust policies."""
        identity = self.identities.get(user_id)
        if not identity:
            raise ValueError("Identity not found")

        now = datetime.now(timezone.utc)
        log_id = f"log-{len(self.access_logs) + 901}"

        if scenario == "impossible_travel":
            # Access from Singapore (1.3521, 103.8198) 2 minutes after previous location
            coords = [1.3521, 103.8198]
            location = "Singapore, SG"
            ip = "118.200.12.9"
            device = "Unknown Android 14 / Linux"
            is_impossible, velocity_kmh, _ = IdentityRiskEngine.evaluate_impossible_travel(
                identity.coordinates, identity.last_login, coords, now
            )
            # High velocity simulation
            velocity_kmh = max(velocity_kmh, 9200.0)

            score, risk_lvl, factors, decision = IdentityRiskEngine.calculate_risk(
                user_role=identity.role,
                privilege_tier=identity.privilege_tier,
                is_quarantined=(identity.status == IdentityStatus.QUARANTINED),
                impossible_travel=True,
                velocity_kmh=velocity_kmh,
                is_abnormal_hour=False,
                unknown_device=True,
                failed_attempts_spike=False,
                tor_or_vpn_exit=False,
                compromised_creds=False
            )

            # Check if policy blocks
            if self.policies.get("pol-1") and self.policies["pol-1"].enabled:
                decision = AccessDecision.BLOCKED

            # Update identity telemetry
            identity.last_login = now
            identity.last_location = location
            identity.last_ip = ip
            identity.coordinates = coords
            identity.risk_score = score
            identity.risk_level = risk_lvl
            identity.status = IdentityStatus.STEP_UP_REQUIRED

            log = AccessLog(
                id=log_id,
                timestamp=now,
                user_id=identity.id,
                user_name=identity.name,
                ip_address=ip,
                location=location,
                coordinates=coords,
                device=device,
                decision=decision,
                risk_score=score,
                risk_factors=factors,
                velocity_kmh=velocity_kmh
            )
            self.add_access_log(log)
            return log

        elif scenario == "brute_force":
            # Credential stuffing attempt
            coords = [55.7558, 37.6173]
            location = "Moscow, RU"
            ip = "195.201.201.14"
            device = "Python-requests / Hydra v9.2"
            
            score, risk_lvl, factors, decision = IdentityRiskEngine.calculate_risk(
                user_role=identity.role,
                privilege_tier=identity.privilege_tier,
                is_quarantined=(identity.status == IdentityStatus.QUARANTINED),
                impossible_travel=False,
                velocity_kmh=0.0,
                is_abnormal_hour=True,
                unknown_device=True,
                failed_attempts_spike=True,
                tor_or_vpn_exit=True,
                compromised_creds=True
            )

            decision = AccessDecision.BLOCKED
            identity.risk_score = score
            identity.risk_level = risk_lvl

            log = AccessLog(
                id=log_id,
                timestamp=now,
                user_id=identity.id,
                user_name=identity.name,
                ip_address=ip,
                location=location,
                coordinates=coords,
                device=device,
                decision=decision,
                risk_score=score,
                risk_factors=factors,
                velocity_kmh=0.0
            )
            self.add_access_log(log)
            return log

        else: # "normal"
            coords = identity.coordinates
            location = identity.last_location
            ip = identity.last_ip
            device = identity.device

            score, risk_lvl, factors, decision = IdentityRiskEngine.calculate_risk(
                user_role=identity.role,
                privilege_tier=identity.privilege_tier,
                is_quarantined=(identity.status == IdentityStatus.QUARANTINED),
                impossible_travel=False,
                velocity_kmh=0.0,
                is_abnormal_hour=False,
                unknown_device=False,
                failed_attempts_spike=False,
                tor_or_vpn_exit=False,
                compromised_creds=False
            )

            identity.last_login = now
            identity.risk_score = score
            identity.risk_level = risk_lvl

            log = AccessLog(
                id=log_id,
                timestamp=now,
                user_id=identity.id,
                user_name=identity.name,
                ip_address=ip,
                location=location,
                coordinates=coords,
                device=device,
                decision=decision,
                risk_score=score,
                risk_factors=factors,
                velocity_kmh=0.0
            )
            self.add_access_log(log)
            return log

# Global singleton state manager
security_state = SecurityStateManager()
