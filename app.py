import base64
import os

import joblib
from flask import Flask, redirect, render_template, request, url_for

from crypto_utils import (
    generate_keys,
    sign_data,
    verify_signature
)

from database import (
    get_events,
    init_db,
    insert_event
)


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

generate_keys()
init_db()

model_data = joblib.load("model/threat_model.pkl")
model = model_data["model"]


def calculate_risk(data):
    features = [[
        data["attempts"],
        data["unknown_device"],
        data["unusual_time"],
        data["verification_failures"],
        data["location_change"],
        data["request_rate"]
    ]]

    probability = model.predict_proba(features)[0][1]

    risk_score = round(probability * 100, 2)

    if risk_score >= 70:
        threat_level = "HIGH"
    elif risk_score >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    result = "SUSPICIOUS" if threat_level != "LOW" else "NORMAL"

    return risk_score, threat_level, result


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        username = request.form["username"]
        document = request.files["document"]

        if document.filename == "":
            return "Please select a file."

        data = document.read()

        signature = sign_data(data)

        signature_b64 = base64.b64encode(signature).decode("utf-8")

        filename = document.filename

        path = os.path.join(UPLOAD_FOLDER, filename)

        with open(path, "wb") as f:
            f.write(data)

        result = {
            "username": username,
            "filename": filename,
            "signature": signature_b64
        }

        return render_template(
            "sign.html",
            result=result
        )

    return render_template("sign.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        document = request.files["document"]

        signature_text = request.form["signature"]

        try:
            signature = base64.b64decode(signature_text)
        except Exception:
            return "Invalid signature format."

        data = document.read()

        valid = verify_signature(data, signature)

        return render_template(
            "verify.html",
            valid=valid
        )

    return render_template("verify.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    username = request.form["username"]

    data = {
        "attempts": int(request.form["attempts"]),
        "unknown_device": int(request.form["unknown_device"]),
        "unusual_time": int(request.form["unusual_time"]),
        "verification_failures": int(
            request.form["verification_failures"]
        ),
        "location_change": int(
            request.form["location_change"]
        ),
        "request_rate": float(
            request.form["request_rate"]
        )
    }

    risk_score, threat_level, result = calculate_risk(data)

    insert_event(
        username=username,
        action="Threat Analysis",
        attempts=data["attempts"],
        unknown_device=data["unknown_device"],
        unusual_time=data["unusual_time"],
        verification_failures=data["verification_failures"],
        location_change=data["location_change"],
        request_rate=data["request_rate"],
        risk_score=risk_score,
        threat_level=threat_level,
        result=result
    )

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    events = get_events()

    return render_template(
        "dashboard.html",
        events=events
    )


if __name__ == "__main__":
    app.run(debug=True)
