from datetime import datetime, timezone, timedelta
from typing import List, Dict
from backend.models import (
    Identity, IdentityStatus, RiskLevel, AccessDecision, 
    AccessLog, SecurityPolicy, Incident, DomainBreachRecord
)

now = datetime.now(timezone.utc)

SAMPLE_IDENTITIES: List[Identity] = [
    Identity(
        id="usr-101",
        name="Elena Rostova",
        email="elena.rostova@cybercorp.internal",
        role="Lead Cryptographic Architect",
        department="Security Engineering",
        status=IdentityStatus.ACTIVE,
        risk_score=14,
        risk_level=RiskLevel.LOW,
        mfa_enabled=True,
        last_login=now - timedelta(minutes=12),
        last_ip="194.26.29.11",
        last_location="Zurich, Switzerland",
        coordinates=[47.3769, 8.5417],
        device="MacBook Pro (Enterprise M3 Max / Secure Enclave)",
        privilege_tier="SuperAdmin",
        active_sessions=1,
        compromised_credentials_detected=False
    ),
    Identity(
        id="usr-102",
        name="Marcus Vance",
        email="marcus.vance@cybercorp.internal",
        role="DevOps Platform Engineer",
        department="Cloud Infrastructure",
        status=IdentityStatus.STEP_UP_REQUIRED,
        risk_score=68,
        risk_level=RiskLevel.HIGH,
        mfa_enabled=True,
        last_login=now - timedelta(minutes=4),
        last_ip="185.220.101.42",
        last_location="Frankfurt, Germany",
        coordinates=[50.1109, 8.6821],
        device="Ubuntu Linux 24.04 (Corporate WireGuard)",
        privilege_tier="Elevated",
        active_sessions=2,
        compromised_credentials_detected=True
    ),
    Identity(
        id="usr-103",
        name="Kaito Tanaka",
        email="kaito.tanaka@cybercorp.internal",
        role="Senior IAM Administrator",
        department="IT Security Operations",
        status=IdentityStatus.QUARANTINED,
        risk_score=92,
        risk_level=RiskLevel.CRITICAL,
        mfa_enabled=False,
        last_login=now - timedelta(minutes=48),
        last_ip="45.154.255.89",
        last_location="Bucharest, Romania",
        coordinates=[44.4268, 26.1025],
        device="Unknown Windows NT (Tor Browser)",
        privilege_tier="SuperAdmin",
        active_sessions=0,
        compromised_credentials_detected=True
    ),
    Identity(
        id="usr-104",
        name="Aria Chen",
        email="aria.chen@cybercorp.internal",
        role="Frontend Engineering Lead",
        department="Core Product",
        status=IdentityStatus.ACTIVE,
        risk_score=22,
        risk_level=RiskLevel.LOW,
        mfa_enabled=True,
        last_login=now - timedelta(hours=2),
        last_ip="142.250.180.14",
        last_location="San Francisco, USA",
        coordinates=[37.7749, -122.4194],
        device="MacBook Air (YubiKey 5C NFC)",
        privilege_tier="Standard",
        active_sessions=1,
        compromised_credentials_detected=False
    ),
    Identity(
        id="usr-105",
        name="David O'Connor",
        email="david.oconnor@cybercorp.internal",
        role="Third-Party Security Auditor",
        department="External Operations",
        status=IdentityStatus.ACTIVE,
        risk_score=45,
        risk_level=RiskLevel.MODERATE,
        mfa_enabled=True,
        last_login=now - timedelta(minutes=30),
        last_ip="82.165.197.1",
        last_location="London, United Kingdom",
        coordinates=[51.5074, -0.1278],
        device="ThinkPad X1 Carbon (Windows 11 Enterprise)",
        privilege_tier="Elevated",
        active_sessions=1,
        compromised_credentials_detected=False
    ),
    Identity(
        id="usr-106",
        name="Siddharth Rao",
        email="siddharth.rao@cybercorp.internal",
        role="Threat Intelligence Analyst",
        department="Cyber Defense Operations",
        status=IdentityStatus.ACTIVE,
        risk_score=18,
        risk_level=RiskLevel.LOW,
        mfa_enabled=True,
        last_login=now - timedelta(minutes=15),
        last_ip="103.21.244.0",
        last_location="Bengaluru, India",
        coordinates=[12.9716, 77.5946],
        device="Fedora Workstation (FIDO2 WebAuthn)",
        privilege_tier="Elevated",
        active_sessions=2,
        compromised_credentials_detected=False
    )
]

SAMPLE_POLICIES: List[SecurityPolicy] = [
    SecurityPolicy(
        id="pol-1",
        name="Impossible Travel Zero-Tolerance Enforcement",
        description="Automatically block access and issue high-severity alert when user velocity exceeds 950 km/h between logins.",
        category="Risk Threshold",
        enabled=True,
        risk_threshold=70,
        action="Block"
    ),
    SecurityPolicy(
        id="pol-2",
        name="Adaptive Step-Up MFA for Elevated Privilege Tiers",
        description="Enforce hardware-bound TOTP / WebAuthn verification when accessing production databases or cloud consoles.",
        category="Authentication",
        enabled=True,
        risk_threshold=40,
        action="Step-Up MFA"
    ),
    SecurityPolicy(
        id="pol-3",
        name="Tor Exit Node & Anonymizing Proxy Immediate Containment",
        description="Deny authentication and place identity into temporary review container if IP matches known threat actor relays.",
        category="Device Security",
        enabled=True,
        risk_threshold=60,
        action="Block"
    ),
    SecurityPolicy(
        id="pol-4",
        name="Compromised Dark Web Credential Automated Quarantine",
        description="Instantly quarantine identities detected in credential dump leaks and invalidate all active session tokens.",
        category="Authentication",
        enabled=True,
        risk_threshold=80,
        action="Quarantine Identity"
    ),
    SecurityPolicy(
        id="pol-5",
        name="Geofenced Perimeter Compliance",
        description="Require approval workflow for logins originating outside primary operational regional clusters (NA, EU, APAC).",
        category="Geo-Fencing",
        enabled=False,
        risk_threshold=50,
        action="Step-Up MFA"
    )
]

SAMPLE_ACCESS_LOGS: List[AccessLog] = [
    AccessLog(
        id="log-901",
        timestamp=now - timedelta(minutes=4),
        user_id="usr-102",
        user_name="Marcus Vance",
        ip_address="185.220.101.42",
        location="Frankfurt, Germany",
        coordinates=[50.1109, 8.6821],
        device="Ubuntu Linux 24.04 (Corporate WireGuard)",
        decision=AccessDecision.CHALLENGED,
        risk_score=68,
        risk_factors=["Credential match on dark web dump", "Session token anomaly"],
        velocity_kmh=120.0
    ),
    AccessLog(
        id="log-902",
        timestamp=now - timedelta(minutes=12),
        user_id="usr-101",
        user_name="Elena Rostova",
        ip_address="194.26.29.11",
        location="Zurich, Switzerland",
        coordinates=[47.3769, 8.5417],
        device="MacBook Pro (Enterprise M3 Max)",
        decision=AccessDecision.GRANTED,
        risk_score=14,
        risk_factors=["Authenticated via FIDO2 token", "Verified posture"],
        velocity_kmh=0.0
    ),
    AccessLog(
        id="log-903",
        timestamp=now - timedelta(minutes=48),
        user_id="usr-103",
        user_name="Kaito Tanaka",
        ip_address="45.154.255.89",
        location="Bucharest, Romania",
        coordinates=[44.4268, 26.1025],
        device="Unknown Windows NT (Tor Relay)",
        decision=AccessDecision.BLOCKED,
        risk_score=92,
        risk_factors=["Impossible Travel: 8,420 km/h from Tokyo", "Known Tor Exit Node", "Identity Quarantined"],
        velocity_kmh=8420.5
    ),
    AccessLog(
        id="log-904",
        timestamp=now - timedelta(hours=1, minutes=10),
        user_id="usr-106",
        user_name="Siddharth Rao",
        ip_address="103.21.244.0",
        location="Bengaluru, India",
        coordinates=[12.9716, 77.5946],
        device="Fedora Workstation (FIDO2 WebAuthn)",
        decision=AccessDecision.GRANTED,
        risk_score=18,
        risk_factors=["Corporate VPN IP match", "Standard work hours"],
        velocity_kmh=45.0
    ),
    AccessLog(
        id="log-905",
        timestamp=now - timedelta(hours=2, minutes=5),
        user_id="usr-104",
        user_name="Aria Chen",
        ip_address="142.250.180.14",
        location="San Francisco, USA",
        coordinates=[37.7749, -122.4194],
        device="MacBook Air (YubiKey 5C NFC)",
        decision=AccessDecision.GRANTED,
        risk_score=22,
        risk_factors=["Routine developer access"],
        velocity_kmh=0.0
    )
]

SAMPLE_INCIDENTS: List[Incident] = [
    Incident(
        id="inc-701",
        title="High-Velocity Impossible Travel & Compromised Admin Session",
        severity=RiskLevel.CRITICAL,
        timestamp=now - timedelta(minutes=48),
        user_id="usr-103",
        user_name="Kaito Tanaka",
        mitre_attack_id="T1078.004",
        mitre_technique="Valid Accounts: Cloud Accounts",
        status="ACTIVE",
        description="Authentication attempted from Bucharest, Romania 15 minutes after Tokyo terminal logout. Associated IP is a verified Tor relay node.",
        ip_address="45.154.255.89",
        recommended_action="Maintain identity quarantine, revoke all active OAuth bearer tokens, force cryptographic password regeneration."
    ),
    Incident(
        id="inc-702",
        title="Elevated Credential Stuffing & Hash Exposure in Dark Web Paste",
        severity=RiskLevel.HIGH,
        timestamp=now - timedelta(minutes=24),
        user_id="usr-102",
        user_name="Marcus Vance",
        mitre_attack_id="T1110.004",
        mitre_technique="Brute Force: Credential Stuffing",
        status="ACTIVE",
        description="Credential hash matching user corporate email observed in Dark Web forum breach database (BreachCollection-2026). Multiple failed SSH handshakes recorded.",
        ip_address="185.220.101.42",
        recommended_action="Enforce step-up FIDO2 authentication challenge; review recent AWS IAM permission grants."
    )
]

SAMPLE_BREACH_RECORDS: Dict[str, List[DomainBreachRecord]] = {
    "cybercorp.internal": [
        DomainBreachRecord(
            source="BreachDirectory Global Leak v4",
            date_leaked="2026-03-14",
            compromised_data=["Corporate Email", "Bcrypt Hash", "Job Title", "SSO Domain"],
            severity=RiskLevel.HIGH
        ),
        DomainBreachRecord(
            source="Exploit.in Telemetry Dump",
            date_leaked="2025-11-20",
            compromised_data=["Plaintext Passwords", "Email Addresses", "API Session Tokens"],
            severity=RiskLevel.CRITICAL
        )
    ],
    "marcus.vance@cybercorp.internal": [
        DomainBreachRecord(
            source="ShadowForum VIP Collection",
            date_leaked="2026-06-02",
            compromised_data=["Email", "MD5 Hash", "DevOps Jenkins Token"],
            severity=RiskLevel.HIGH
        )
    ],
    "kaito.tanaka@cybercorp.internal": [
        DomainBreachRecord(
            source="StealerLog RedLine Aggregator",
            date_leaked="2026-08-19",
            compromised_data=["Browser Cookies", "Autofill Passwords", "Okta Session Keys"],
            severity=RiskLevel.CRITICAL
        )
    ]
}
