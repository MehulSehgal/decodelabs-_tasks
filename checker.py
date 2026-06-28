"""
Password Strength Checker - Core Logic
DecodeLabs Industrial Training Kit | Batch 2026
Author: Intern | Project 1 - Cybersecurity Track

This module handles the actual strength evaluation logic.
Uses Python string methods and conditional checks — no regex overkill.
"""

import string
import hmac


# A small set of the most commonly used / leaked passwords
# In a real system you'd load from a file like rockyou.txt subset
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "superman",
    "iloveyou", "sunshine", "princess", "dragon", "master",
    "welcome", "login", "admin123", "pass", "test123",
    "password1", "12345678", "shadow", "football", "baseball"
}


def check_length(password: str) -> dict:
    """
    Length is the first and most important check.
    < 8 chars = automatic fail (exponential brute-force risk)
    """
    length = len(password)
    if length < 8:
        return {"pass": False, "length": length, "note": "Too short — minimum 8 characters required"}
    elif length < 12:
        return {"pass": True, "length": length, "note": "Acceptable length"}
    elif length < 16:
        return {"pass": True, "length": length, "note": "Good length"}
    else:
        return {"pass": True, "length": length, "note": "Excellent length"}


def check_character_variety(password: str) -> dict:
    """
    Checks presence of:
    - Uppercase letters [A-Z]
    - Lowercase letters [a-z]
    - Digits [0-9]
    - Special symbols
    
    Uses Pythonic 'any()' approach with short-circuit evaluation
    instead of verbose manual loops.
    """
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    return {
        "uppercase": has_upper,
        "lowercase": has_lower,
        "digit":     has_digit,
        "symbol":    has_symbol,
        "variety_score": score  # 0 to 4
    }


def check_common_password(password: str) -> bool:
    """
    Returns True if password is in the common/leaked list.
    Case-insensitive comparison.
    Uses hmac.compare_digest to avoid timing attacks
    when comparing against each entry.
    """
    pw_lower = password.lower()
    for common in COMMON_PASSWORDS:
        # constant-time comparison — prevents timing side-channel leaks
        if hmac.compare_digest(pw_lower, common):
            return True
    return False


def check_repeated_chars(password: str) -> bool:
    """
    Detects patterns like 'aaaa' or '1111' that reduce entropy.
    Simple sequential check — O(n) linear scan as required.
    """
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True  # Three or more same chars in a row
    return False


def calculate_strength(password: str) -> dict:
    """
    Master function — aggregates all checks and returns a result dict.
    
    Scoring logic:
      Weak   → fails length OR is a common password
      Medium → passes length, has 2-3 character varieties
      Strong → passes all checks, has 4 varieties, no repeated chars
    """
    if not password:
        return {
            "strength": "INVALID",
            "score": 0,
            "feedback": ["Password cannot be empty."],
            "details": {}
        }

    length_check  = check_length(password)
    variety_check = check_character_variety(password)
    is_common     = check_common_password(password)
    has_repeats   = check_repeated_chars(password)

    feedback = []
    score = 0

    # --- Length scoring ---
    if not length_check["pass"]:
        feedback.append(f"Too short ({length_check['length']} chars). Use at least 8.")
    else:
        if length_check["length"] >= 16:
            score += 3
        elif length_check["length"] >= 12:
            score += 2
        else:
            score += 1

    # --- Common password check ---
    if is_common:
        feedback.append("This is a commonly used password — easily cracked.")
        score = 0  # Hard reset; doesn't matter how complex it looks

    # --- Character variety scoring ---
    variety = variety_check["variety_score"]
    score += variety

    if not variety_check["uppercase"]:
        feedback.append("Add at least one uppercase letter (A-Z).")
    if not variety_check["digit"]:
        feedback.append("Add at least one number (0-9).")
    if not variety_check["symbol"]:
        feedback.append("Add at least one symbol (e.g. @, #, !).")
    if not variety_check["lowercase"]:
        feedback.append("Add at least one lowercase letter.")

    # --- Repeated character penalty ---
    if has_repeats:
        score -= 1
        feedback.append("Avoid repeating characters (e.g. 'aaa' or '111').")

    # --- Final classification ---
    if is_common or not length_check["pass"]:
        strength = "WEAK"
    elif score <= 3:
        strength = "WEAK"
    elif score <= 5:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    if not feedback:
        feedback.append("Password looks solid. Good work!")

    return {
        "strength": strength,
        "score": max(0, score),
        "feedback": feedback,
        "details": {
            "length":    length_check,
            "variety":   variety_check,
            "is_common": is_common,
            "has_repeats": has_repeats
        }
    }
