import sys
import os
from datetime import datetime, timezone, timedelta

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.crypto_security import TOTPGenerator, PasswordAuditor
from backend.risk_engine import IdentityRiskEngine, haversine_distance_km
from backend.models import RiskLevel, AccessDecision
from backend.policy_engine import security_state

def test_totp():
    print("Testing TOTP Engine...")
    secret = TOTPGenerator.generate_secret()
    token, remaining = TOTPGenerator.get_totp_token(secret)
    assert len(token) == 6, f"Expected 6 digit token, got {token}"
    assert 0 <= remaining <= 30, f"Remaining time out of bounds: {remaining}"
    assert TOTPGenerator.verify_token(secret, token) is True, "Token verification failed"
    assert TOTPGenerator.verify_token(secret, "000000") is False, "Invalid token passed verification"
    print("[OK] TOTP Engine passed")

def test_password_auditor():
    print("Testing Password Auditor...")
    weak = PasswordAuditor.audit("password")
    assert weak["is_compromised"] is True, "Expected 'password' to be marked compromised"
    assert weak["score"] <= 30, "Compromised password score too high"

    strong = PasswordAuditor.audit("K7#vX9$mQ2!zL5@p")
    assert strong["entropy_bits"] > 70, f"Strong password entropy was {strong['entropy_bits']}"
    assert strong["strength"] in ["Strong", "Military-Grade"]
    print("[OK] Password Auditor passed")

def test_risk_engine():
    print("Testing Risk Engine & Haversine Distance...")
    # Distance between London (51.5074, -0.1278) and Tokyo (35.6762, 139.6503) is ~9560 km
    dist = haversine_distance_km([51.5074, -0.1278], [35.6762, 139.6503])
    assert 9000 < dist < 10000, f"Unexpected distance: {dist}"

    now = datetime.now(timezone.utc)
    is_imp, vel, _ = IdentityRiskEngine.evaluate_impossible_travel(
        [51.5074, -0.1278], now - timedelta(minutes=15),
        [35.6762, 139.6503], now
    )
    assert is_imp is True, "Expected impossible travel to be True"
    assert vel > 20000, f"Expected velocity > 20000 km/h, got {vel}"

    score, level, factors, decision = IdentityRiskEngine.calculate_risk(
        user_role="Admin",
        privilege_tier="SuperAdmin",
        is_quarantined=False,
        impossible_travel=True,
        velocity_kmh=vel,
        is_abnormal_hour=False,
        unknown_device=True,
        failed_attempts_spike=False,
        tor_or_vpn_exit=False,
        compromised_creds=False
    )
    assert score >= 60, f"Expected high risk score, got {score}"
    assert level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert decision in [AccessDecision.CHALLENGED, AccessDecision.BLOCKED]
    print("[OK] Risk Engine passed")

def test_state_manager():
    print("Testing Security State Manager...")
    user = security_state.get_identity("usr-104")
    assert user is not None
    assert user.name == "Aria Chen"

    # Test Quarantine
    q_user = security_state.quarantine_identity("usr-104")
    assert q_user.status.value == "QUARANTINED"
    assert q_user.risk_score == 100

    # Test Restore
    r_user = security_state.unquarantine_identity("usr-104")
    assert r_user.status.value == "ACTIVE"
    assert r_user.risk_score == 15

    # Test Simulation
    sim_log = security_state.simulate_event("usr-104", "impossible_travel")
    assert sim_log.risk_score >= 50
    print("[OK] Security State Manager passed")

if __name__ == "__main__":
    test_totp()
    test_password_auditor()
    test_risk_engine()
    test_state_manager()
    print("\nALL BACKEND UNIT TESTS PASSED SUCCESSFULLY! [PASS]")
