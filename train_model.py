import os

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


FEATURES = [
    "attempts",
    "unknown_device",
    "unusual_time",
    "verification_failures",
    "location_change",
    "request_rate"
]


def create_dataset():
    np.random.seed(42)

    rows = []

    # Normal events
    for _ in range(500):
        attempts = np.random.randint(1, 6)
        unknown_device = np.random.choice([0, 1], p=[0.95, 0.05])
        unusual_time = np.random.choice([0, 1], p=[0.95, 0.05])
        verification_failures = np.random.randint(0, 3)
        location_change = np.random.choice([0, 1], p=[0.98, 0.02])
        request_rate = np.random.uniform(0.1, 2.0)

        rows.append([
            attempts,
            unknown_device,
            unusual_time,
            verification_failures,
            location_change,
            request_rate,
            0
        ])

    # Suspicious events
    for _ in range(500):
        attempts = np.random.randint(15, 100)
        unknown_device = np.random.choice([0, 1], p=[0.15, 0.85])
        unusual_time = np.random.choice([0, 1], p=[0.20, 0.80])
        verification_failures = np.random.randint(8, 50)
        location_change = np.random.choice([0, 1], p=[0.25, 0.75])
        request_rate = np.random.uniform(5.0, 30.0)

        rows.append([
            attempts,
            unknown_device,
            unusual_time,
            verification_failures,
            location_change,
            request_rate,
            1
        ])

    columns = FEATURES + ["label"]

    return pd.DataFrame(rows, columns=columns)


def main():
    df = create_dataset()

    X = df[FEATURES]
    y = df["label"]

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, y)

    os.makedirs("model", exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": FEATURES
        },
        "model/threat_model.pkl"
    )

    df.to_csv("model/security_dataset.csv", index=False)

    print("Model trained successfully.")


if __name__ == "__main__":
    main()
