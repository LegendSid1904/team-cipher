"""Threat detection combining rule-based scoring with the
quantum-inspired Random Forest model.

This is the serverless-friendly equivalent of the original
project's detector.py. Each request stays self-contained; behavioral
history is supplied by ``behavioral_store`` and model prediction by
``ml_detector``.
"""

from . import ml_detector


def _compute_risk_score(
    valid: bool,
    key_size: int,
    verification_frequency: int = 1,
    source_frequency: int = 1,
    failed_verification_rate: float = 0.0,
    metadata_anomaly: int = 0,
    replay_indicator: int = 0,
) -> tuple:
    score = 0
    reasons = []

    if not valid:
        score += 30
        reasons.append("Digital signature verification failed")

    if 0 < key_size < 2048:
        score += 15
        reasons.append(f"Weak RSA key size ({key_size} bits)")

    if failed_verification_rate >= 0.6:
        score += 20
        reasons.append("High rate of failed verifications")

    if replay_indicator:
        score += 15
        reasons.append("Previously processed document detected (replay)")

    if metadata_anomaly:
        score += 10
        reasons.append("Suspicious document metadata detected")

    if source_frequency >= 40:
        score += 10
        reasons.append("Unusually high verification activity from source")

    if verification_frequency >= 30:
        score += 5
        reasons.append("Unusually high verification frequency")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def _determine_attack_category(
    valid: bool,
    key_size: int,
    metadata_anomaly: int = 0,
    replay_indicator: int = 0,
    failed_verification_rate: float = 0.0,
    source_frequency: int = 1,
    verification_frequency: int = 1,
) -> str:
    indicators = int(not valid) + int(metadata_anomaly) + int(replay_indicator)

    if indicators >= 3:
        return "COMBINED_THREAT"

    if not valid:
        if 0 < key_size < 2048:
            return "WEAK_KEY_TAMPERING"
        return "DOCUMENT_TAMPERING"

    if replay_indicator:
        return "REPLAY"

    if 0 < key_size < 2048:
        return "WEAK_KEY"

    if (
        failed_verification_rate >= 0.6
        or source_frequency >= 40
        or verification_frequency >= 30
    ):
        return "BEHAVIORAL_ANOMALY"

    if metadata_anomaly:
        return "METADATA_ANOMALY"

    return "BENIGN"


def detect_threat(
    valid: bool,
    key_size: int,
    verification_frequency: int = 1,
    source_frequency: int = 1,
    failed_verification_rate: float = 0.0,
    metadata_anomaly: int = 0,
    replay_indicator: int = 0,
    failed_attempts: int = 0,
) -> dict:
    """Run rule-based + ML detection and return a full report."""
    if not isinstance(verification_frequency, int):
        verification_frequency = int(verification_frequency or 0)
    if not isinstance(source_frequency, int):
        source_frequency = int(source_frequency or 0)
    if failed_verification_rate is None:
        failed_verification_rate = 0.0

    key_size = int(key_size) if key_size else -1

    risk_score, level, reasons = _compute_risk_score(
        valid,
        key_size,
        verification_frequency,
        source_frequency,
        failed_verification_rate,
        metadata_anomaly,
        replay_indicator,
    )

    category = _determine_attack_category(
        valid,
        key_size,
        metadata_anomaly,
        replay_indicator,
        failed_verification_rate,
        source_frequency,
        verification_frequency,
    )

    # ---- ML prediction --------------------------------------
    ml_event = {
        "verification_result": 1 if valid else 0,
        "failed_attempts": int(failed_attempts),
        "certificate_valid": 1,
        "source_frequency": source_frequency,
        "failed_verification_rate": float(failed_verification_rate),
        "metadata_anomaly": int(metadata_anomaly),
        "replay_indicator": int(replay_indicator),
    }

    try:
        ml = ml_detector.predict_threat(ml_event)
    except Exception:
        ml = {
            "ml_loaded": False,
            "ml_prediction": "NORMAL",
            "ml_threat_probability": 0.0,
        }

    # ---- assessment -----------------------------------------
    if ml["ml_prediction"] == "THREAT" and risk_score >= 70:
        assessment = "HIGH-RISK SECURITY EVENT"
    elif ml["ml_prediction"] == "THREAT" or risk_score >= 40:
        assessment = "SUSPICIOUS SECURITY EVENT"
    else:
        assessment = "NORMAL SECURITY EVENT"

    # ---- cryptographic security override ---------------------
    # A cryptographically invalid document must never be
    # presented as a normal / low-risk event. Preserve the actual
    # ML prediction but raise the risk floor to suspicious.
    if not valid:
        risk_score = max(risk_score, 40)
        if level == "LOW":
            level = "MEDIUM"
        if assessment == "NORMAL SECURITY EVENT":
            assessment = "SUSPICIOUS SECURITY EVENT"
        if "Digital signature verification failed" not in reasons:
            reasons.insert(0, "Digital signature verification failed")

    explanation = _generate_explanation(
        valid, key_size, risk_score, level, ml, replay_indicator,
        failed_verification_rate, metadata_anomaly,
    )
    actions = _generate_actions(level, valid, category)

    if ml["ml_prediction"] == "THREAT":
        reasons.insert(0, "ML detected suspicious behavioral pattern")

    return {
        "signature_verification": "VALID" if valid else "INVALID",
        "ml_prediction": ml["ml_prediction"],
        "ml_threat_probability": ml["ml_threat_probability"],
        "ml_loaded": ml["ml_loaded"],
        "risk_score": risk_score,
        "threat_level": level,
        "attack_category": category,
        "contributing_indicators": reasons,
        "assessment": assessment,
        "assessment_explanation": explanation,
        "recommended_action": actions,
    }


def _generate_explanation(
    valid: bool,
    key_size: int,
    risk_score: int,
    level: str,
    ml: dict,
    replay_indicator: int,
    failed_verification_rate: float,
    metadata_anomaly: int,
) -> list:
    explanation = []

    if ml.get("ml_loaded"):
        explanation.append(
            "ML: "
            + (
                "detected suspicious behavioral patterns."
                if ml["ml_prediction"] == "THREAT"
                else "no strong threat pattern detected."
            )
        )
    else:
        explanation.append("ML model unavailable — rule-based analysis only.")

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
        explanation.append(f"Public key strength is {key_size} bits.")

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

    if replay_indicator:
        explanation.append("Replay-like activity was observed.")

    if failed_verification_rate >= 0.6:
        explanation.append("Historical verification behavior shows a high failure rate.")

    if metadata_anomaly:
        explanation.append("Suspicious document metadata was observed.")

    if level == "HIGH":
        explanation.append("Immediate attention is recommended.")
    elif level == "MEDIUM":
        explanation.append("Further review is recommended.")
    else:
        explanation.append("No urgent action is required.")

    return explanation


def _generate_actions(level: str, valid: bool, category: str) -> list:
    if not valid:
        return [
            "Do not trust the document.",
            "Flag for investigation.",
            "Request a fresh signature from the signer.",
        ]

    if category == "REPLAY":
        return [
            "This document was processed before.",
            "Verify whether legitimate resubmission.",
            "Flag possible replay attack.",
        ]

    if level == "HIGH":
        return [
            "Investigate the source.",
            "Review recent verification history.",
        ]

    if level == "MEDIUM":
        return [
            "Monitor subsequent requests from the source.",
        ]

    return [
        "No immediate action required.",
        "Continue normal monitoring.",
    ]