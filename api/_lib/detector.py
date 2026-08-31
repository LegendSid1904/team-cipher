"""Rule-based threat detection engine.

This is the serverless-friendly equivalent of detector.py from the
original project. It has NO persistence dependency — each request is
self-contained.

A small in-memory attempt tracker provides basic behavioral signal
(failed-attempt streaks and frequency) that survives while the
serverless instance is warm. Because Vercel functions can be
cold-started / reset at any time, this state is best-effort and
documented as such.
"""

# Keep a module-level attempt history so a warm instance can
# show rising risk as a user submits multiple bad documents.
# This resets on cold start — acceptable for a demo.
_ATTEMPT_LOG = {
    "count": 0,
    "failed_count": 0,
    "last_success": True,
}


def record_attempt(valid: bool):
    _ATTEMPT_LOG["count"] += 1
    if not valid:
        _ATTEMPT_LOG["failed_count"] += 1
    _ATTEMPT_LOG["last_success"] = valid


def _compute_risk_score(valid: bool, key_size: int) -> tuple:
    score = 0
    reasons = []

    if not valid:
        score += 30
        reasons.append("Digital signature verification failed")

    if key_size > 0 and key_size < 2048:
        score += 15
        reasons.append(f"Weak RSA key size ({key_size} bits)")

    total = _ATTEMPT_LOG["count"]
    failed = _ATTEMPT_LOG["failed_count"]

    if total >= 4:
        score += 10
        reasons.append("High number of verification attempts in session")

    if total > 0 and (failed / total) >= 0.6:
        score += 20
        reasons.append("High rate of failed verifications")

    if failed >= 3:
        score += 15
        reasons.append("Multiple consecutive failed verifications")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def determine_attack_category(valid: bool, key_size: int) -> str:
    if not valid:
        if key_size > 0 and key_size < 2048:
            return "WEAK_KEY_TAMPERING"
        return "DOCUMENT_TAMPERING"
    if key_size > 0 and key_size < 2048:
        return "WEAK_KEY"
    return "BENIGN"


def generate_explanation(
    valid: bool,
    key_size: int,
    risk_score: int,
    level: str
) -> list:
    explanation = []

    if valid:
        explanation.append(
            "The digital signature verified successfully with the "
            "supplied public key."
        )
    else:
        explanation.append(
            "The digital signature could not be verified against the "
            "supplied public key."
        )

    if key_size > 0:
        explanation.append(
            f"Public key strength is {key_size} bits."
        )

    if risk_score < 40:
        explanation.append(
            "Rule-based indicators are below the medium-risk threshold."
        )
    elif risk_score < 70:
        explanation.append(
            "Rule-based indicators indicate a medium-risk event."
        )
    else:
        explanation.append(
            "Multiple indicators indicate a high-risk event."
        )

    if level == "HIGH":
        explanation.append(
            "Immediate attention is recommended."
        )
    elif level == "MEDIUM":
        explanation.append(
            "Further review is recommended."
        )
    else:
        explanation.append(
            "No urgent action is required."
        )

    return explanation


def generate_actions(level: str, valid: bool) -> list:
    if not valid:
        return [
            "Do not trust the document.",
            "Flag for investigation.",
            "Request a fresh signature from the signer."
        ]
    if level == "HIGH":
        return [
            "Investigate the source.",
            "Review recent verification history."
        ]
    if level == "MEDIUM":
        return [
            "Monitor subsequent requests from the source."
        ]
    return [
        "No immediate action required.",
        "Continue normal monitoring."
    ]


def detect_threat(valid: bool, key_size: int) -> dict:
    record_attempt(valid)
    key_size = int(key_size) if key_size else -1

    risk_score, level, reasons = _compute_risk_score(valid, key_size)
    category = determine_attack_category(valid, key_size)

    if level == "HIGH":
        assessment = "HIGH-RISK SECURITY EVENT"
    elif level == "MEDIUM":
        assessment = "SUSPICIOUS SECURITY EVENT"
    else:
        assessment = "NORMAL SECURITY EVENT"

    explanation = generate_explanation(
        valid, key_size, risk_score, level
    )
    actions = generate_actions(level, valid)

    return {
        "signature_verification": "VALID" if valid else "INVALID",
        "risk_score": risk_score,
        "threat_level": level,
        "attack_category": category,
        "contributing_indicators": reasons,
        "assessment": assessment,
        "assessment_explanation": explanation,
        "recommended_action": actions,
    }
