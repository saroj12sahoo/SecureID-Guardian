import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from backend.models import RiskLevel, AccessDecision

def haversine_distance_km(coord1: List[float], coord2: List[float]) -> float:
    """Calculates great-circle distance between two (lat, lon) points in kilometers."""
    lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
    lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    r = 6371.0 # Earth radius in km
    return r * c

class IdentityRiskEngine:
    """UEBA Behavioral Anomaly & Identity Risk Evaluation Engine."""

    # Maximum feasible commercial airline speed + transit overhead: 950 km/h
    MAX_FEASIBLE_VELOCITY_KMH = 950.0

    @classmethod
    def evaluate_impossible_travel(
        cls, 
        last_coords: List[float], 
        last_time: datetime, 
        new_coords: List[float], 
        new_time: datetime
    ) -> Tuple[bool, float, float]:
        """
        Determines if access between two coordinates in the given elapsed time 
        constitutes 'impossible travel'. Returns (is_impossible, velocity_kmh, distance_km).
        """
        distance_km = haversine_distance_km(last_coords, new_coords)
        time_diff_hours = abs((new_time - last_time).total_seconds()) / 3600.0

        if time_diff_hours <= 0.001:
            velocity_kmh = distance_km / 0.001 if distance_km > 50 else 0.0
        else:
            velocity_kmh = distance_km / time_diff_hours

        is_impossible = (distance_km > 200.0) and (velocity_kmh > cls.MAX_FEASIBLE_VELOCITY_KMH)
        return is_impossible, round(velocity_kmh, 1), round(distance_km, 1)

    @classmethod
    def calculate_risk(
        cls,
        user_role: str,
        privilege_tier: str,
        is_quarantined: bool,
        impossible_travel: bool,
        velocity_kmh: float,
        is_abnormal_hour: bool,
        unknown_device: bool,
        failed_attempts_spike: bool,
        tor_or_vpn_exit: bool,
        compromised_creds: bool
    ) -> Tuple[int, RiskLevel, List[str], AccessDecision]:
        """
        Synthesizes multiple behavioral telemetry signals into an aggregate risk score (0-100),
        an enumerated risk tier, contextual risk factors, and access decision.
        """
        if is_quarantined:
            return 100, RiskLevel.CRITICAL, ["Identity is Quarantined / Contained"], AccessDecision.BLOCKED

        base_score = 5
        risk_factors = []

        # High-Privilege Target adjustment
        if privilege_tier in ["SuperAdmin", "Elevated"]:
            base_score += 10
            risk_factors.append("High-Value Privileged Identity (Admin Tier)")

        # Impossible Travel
        if impossible_travel:
            base_score += 50
            risk_factors.append(f"Impossible Travel Detected ({velocity_kmh:,.0f} km/h)")

        # Compromised credentials detected
        if compromised_creds:
            base_score += 40
            risk_factors.append("Compromised Credentials / Dark Web Hash Match")

        # Tor / High-Risk Proxy Exit Node
        if tor_or_vpn_exit:
            base_score += 30
            risk_factors.append("Access originating from known Tor Exit Node / Malicious Proxy")

        # Brute force / credential stuffing spike
        if failed_attempts_spike:
            base_score += 35
            risk_factors.append("Brute-Force Anomaly: Elevated failed authentication burst")

        # Unknown / Unmanaged Device
        if unknown_device:
            base_score += 15
            risk_factors.append("Unrecognized Device Fingerprint / Missing Hardware Token")

        # Abnormal hour
        if is_abnormal_hour:
            base_score += 10
            risk_factors.append("Off-Hours Access: Login outside typical user activity window")

        final_score = min(100, max(0, base_score))

        # Risk Tier Classification
        if final_score >= 80:
            risk_level = RiskLevel.CRITICAL
            decision = AccessDecision.BLOCKED
        elif final_score >= 60:
            risk_level = RiskLevel.HIGH
            decision = AccessDecision.CHALLENGED
        elif final_score >= 30:
            risk_level = RiskLevel.MODERATE
            decision = AccessDecision.CHALLENGED
        else:
            risk_level = RiskLevel.LOW
            decision = AccessDecision.GRANTED

        if not risk_factors:
            risk_factors.append("Telemetry within normal baseline behavior")

        return final_score, risk_level, risk_factors, decision
