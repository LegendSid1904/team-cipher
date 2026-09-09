"""Machine-learning threat-detection engine.

Loads the trained quantum-inspired Random Forest model
(``models/random_forest_qi_day7.pkl``) once per warm instance and
serves predictions on the 7 quantum-inspired selected features.

If the model cannot be loaded (missing / incompatible file during a
cold start), the module degrades to ``no-ML`` mode and the caller
falls back to pure rule-based detection.
"""

import os
import joblib
import pandas as pd

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "random_forest_qi_day7.pkl",
)

# The 7 quantum-inspired selected features used at training time.
QI_FEATURES = [
    "verification_result",
    "failed_attempts",
    "certificate_valid",
    "source_frequency",
    "failed_verification_rate",
    "metadata_anomaly",
    "replay_indicator",
]

_MODEL = None
_LOAD_ERROR = None


def _load():
    """Return the loaded model, or None if unavailable."""
    global _MODEL, _LOAD_ERROR

    if _MODEL is not None:
        return _MODEL

    if _LOAD_ERROR is not None:
        return None

    if not os.path.exists(MODEL_PATH):
        _LOAD_ERROR = f"Model file not found: {MODEL_PATH}"
        return None

    try:
        _MODEL = joblib.load(MODEL_PATH)
    except Exception as e:  # pragma: no cover - depends on local env
        _LOAD_ERROR = f"Failed to load model: {e}"
        _MODEL = None

    return _MODEL


def model_loaded() -> bool:
    return _load() is not None


def load_error():
    """Return the last model-load error message, or None."""
    return _LOAD_ERROR


def predict_threat(event: dict) -> dict:
    """Run ML inference on an event dict.

    Expects the 7 QI feature keys. Returns a dict with:

      - ``ml_loaded``: bool
      - ``ml_prediction``: "THREAT" | "NORMAL"
      - ``ml_threat_probability``: float (percentage)

    If the model is unavailable, returns a no-ML result whose
    ``ml_loaded`` is False (caller can fall back to rules).
    """
    model = _load()

    if model is None:
        return {
            "ml_loaded": False,
            "ml_prediction": "NORMAL",
            "ml_threat_probability": 0.0,
        }

    missing = [f for f in QI_FEATURES if f not in event]
    if missing:
        raise ValueError(
            "Missing ML model features: " + ", ".join(missing)
        )

    dataframe = pd.DataFrame(
        [{feature: event[feature] for feature in QI_FEATURES}]
    )

    prediction = int(model.predict(dataframe)[0])
    probability = float(model.predict_proba(dataframe)[0][1])

    return {
        "ml_loaded": True,
        "ml_prediction": "THREAT" if prediction == 1 else "NORMAL",
        "ml_threat_probability": round(probability * 100, 2),
    }