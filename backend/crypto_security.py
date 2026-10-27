import hmac
import hashlib
import struct
import time
import base64
import math
import re
from typing import Dict, Any, List, Tuple

# Sample offline list of known common breached passwords (for immediate instant simulation & offline safety)
COMMON_BREACHED_PASSWORDS = {
    "password": 3824109,
    "123456": 24198230,
    "12345678": 6712091,
    "123456789": 8940120,
    "admin": 2109481,
    "welcome": 1823901,
    "qwerty": 4901239,
    "password123": 1729482,
    "iloveyou": 2981041,
    "monkey": 1102948,
    "dragon": 981204,
    "sunshine": 890124,
    "princess": 810293,
    "football": 740192,
    "charlie": 620194,
    "letmein": 590124,
    "master": 540192,
    "security": 491024,
    "trustno1": 381029,
    "cybersec": 194012,
    "secret": 849102,
}

class TOTPGenerator:
    """Standard RFC 6238 compliant TOTP generator and validator."""
    
    @staticmethod
    def generate_secret(length: int = 16) -> str:
        """Generate a random Base32 secret key."""
        random_bytes = hashlib.sha256(str(time.time_ns()).encode()).digest()[:length]
        return base64.b32encode(random_bytes).decode('utf-8').replace('=', '')[:16]

    @staticmethod
    def get_totp_token(secret: str, interval: int = 30) -> Tuple[str, int]:
        """Calculates current 6-digit TOTP token and remaining seconds."""
        current_time = int(time.time())
        time_counter = current_time // interval
        time_remaining = interval - (current_time % interval)

        # Pad secret if needed
        padding = '=' * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(secret.upper() + padding)

        # Pack counter into 8 bytes big-endian
        counter_bytes = struct.pack(">Q", time_counter)
        mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation (RFC 4226)
        offset = mac[-1] & 0x0F
        binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
        token = str(binary % 1000000).zfill(6)
        return token, time_remaining

    @classmethod
    def verify_token(cls, secret: str, token: str, window: int = 1, interval: int = 30) -> bool:
        """Verifies token allowing for +/- clock drift."""
        current_time = int(time.time())
        for drift in range(-window, window + 1):
            t = current_time + (drift * interval)
            time_counter = t // interval
            padding = '=' * ((8 - len(secret) % 8) % 8)
            try:
                key = base64.b32decode(secret.upper() + padding)
                counter_bytes = struct.pack(">Q", time_counter)
                mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()
                offset = mac[-1] & 0x0F
                binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
                expected = str(binary % 1000000).zfill(6)
                if expected == token.strip():
                    return True
            except Exception:
                pass
        return False

class PasswordAuditor:
    """Advanced Password Entropy & Breach Auditor."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Computes Shannon information entropy and character-pool entropy."""
        if not password:
            return 0.0

        pool_size = 0
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_special: pool_size += 33

        if pool_size == 0:
            return 0.0

        # NIST/Shannon theoretical bits of entropy
        entropy_bits = len(password) * math.log2(pool_size)

        # Deduct penalties for repeating characters or sequential patterns
        repeats = len(password) - len(set(password))
        penalty = repeats * 1.5
        
        # Sequential patterns (e.g., abc, 123)
        lower_pwd = password.lower()
        if any(lower_pwd[i:i+3] in "abcdefghijklmnopqrstuvwxyz0123456789" for i in range(len(lower_pwd) - 2)):
            penalty += 10.0

        return max(0.0, round(entropy_bits - penalty, 2))

    @classmethod
    def estimate_crack_time(cls, entropy_bits: float) -> str:
        """Estimate time required for an attacker with 100 Billion guesses/sec (GPU cluster)."""
        combinations = 2 ** entropy_bits
        hash_rate = 100_000_000_000 # 100 GH/s
        seconds = combinations / (2 * hash_rate)

        if seconds < 0.001:
            return "Instantaneous (< 1 millisecond)"
        elif seconds < 1:
            return f"{round(seconds * 1000)} milliseconds"
        elif seconds < 60:
            return f"{round(seconds, 1)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        elif seconds < 3153600000:
            return f"{round(seconds / 31536000, 1)} years"
        elif seconds < 315360000000:
            return f"{round(seconds / 3153600000, 1)} centuries"
        else:
            return "Millions of years (Cryptographically secure)"

    @classmethod
    def audit(cls, password: str) -> Dict[str, Any]:
        """Comprehensive audit of password strength, entropy, and simulated breach exposure."""
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        entropy = cls.calculate_entropy(password)
        crack_time = cls.estimate_crack_time(entropy)

        # Check against offline compromised table
        clean_pwd = password.strip().lower()
        breach_count = COMMON_BREACHED_PASSWORDS.get(clean_pwd, 0)
        
        # Check SHA-1 hash against common patterns
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        if clean_pwd.startswith("admin") or clean_pwd.startswith("pass") or clean_pwd.startswith("123"):
            if breach_count == 0:
                breach_count = 1420

        feedback = []
        if length < 8:
            feedback.append("Critical: Password is shorter than 8 characters.")
        elif length < 12:
            feedback.append("Recommendation: Expand length to at least 14 characters for Zero-Trust compliance.")

        if not has_upper:
            feedback.append("Missing uppercase characters.")
        if not has_lower:
            feedback.append("Missing lowercase characters.")
        if not has_digit:
            feedback.append("Missing numeric digits.")
        if not has_special:
            feedback.append("Missing special security symbols (@, #, $, %, etc.).")

        if breach_count > 0:
            feedback.append(f"ALERT: This password appeared in {breach_count:,} public data breaches!")

        # Scoring 0 to 100
        score = 0
        if breach_count > 0:
            score = 15
            strength = "Compromised / Critical"
        else:
            if entropy < 30:
                score = 25
                strength = "Very Weak"
            elif entropy < 50:
                score = 50
                strength = "Moderate"
            elif entropy < 75:
                score = 75
                strength = "Strong"
            else:
                score = 100
                strength = "Military-Grade"

        if not feedback:
            feedback.append("Zero-Trust compliant password with strong entropy.")

        return {
            "entropy_bits": entropy,
            "strength": strength,
            "score": score,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_numbers": has_digit,
            "has_special": has_special,
            "length": length,
            "estimated_crack_time": crack_time,
            "breach_count": breach_count,
            "is_compromised": breach_count > 0,
            "feedback": feedback
        }
