"use strict";

const $ = (id) => document.getElementById(id);

function wireFileField(inputId, boxId) {
    const input = $(inputId);
    const box = $(boxId);
    input.addEventListener("change", () => {
        const file = input.files[0];
        if (file) {
            box.classList.add("selected");
            box.querySelector(".file-name").textContent = "selected: " + file.name;
        } else {
            box.classList.remove("selected");
            box.querySelector(".file-name").textContent = "selected: none";
        }
    });
}
wireFileField("documentInput", "boxDocument");
wireFileField("signatureInput", "boxSignature");

const verifyBtn = $("verifyBtn");
const loading = $("loading");
const errorBox = $("errorBox");

verifyBtn.addEventListener("click", async () => {
    hideError();

    const doc = $("documentInput").files[0];
    const sig = $("signatureInput").files[0];
    const key = $("keyInput").value.trim();

    if (!doc) return showError("Select the document file.");
    if (!sig) return showError("Select the signature (.sig) file — it's created when you sign the document.");
    if (!key) return showError("Paste the public key (copy it from the Sign page).");

    const formData = new FormData();
    formData.append("document", doc);
    formData.append("signature", sig);
    formData.append("public_key", key);

    verifyBtn.disabled = true;
    loading.classList.remove("hidden");
    $("result").classList.add("hidden");

    try {
        const res = await fetch(`/api/verify`, { method: "POST", body: formData });
        const data = await res.json().catch(() => null);

        if (!res.ok || !data || data.success !== true) {
            const detail = data && data.detail ? data.detail : "Verification failed.";
            throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
        }

        displayResult(data.result);
    } catch (err) {
        showError(err.message);
    } finally {
        verifyBtn.disabled = false;
        loading.classList.add("hidden");
    }
});

function displayResult(r) {
    const valid = r.signature_verification === "VALID";

    $("verifyStatus").textContent = valid ? "VALID" : "INVALID";
    $("verifyStatus").className = "auth-status " + (valid ? "ok" : "bad");
    $("authIcon").textContent = valid ? "✓" : "✕";
    $("authIcon").className = "auth-icon " + (valid ? "ok" : "bad");
    $("verifySub").textContent = valid
        ? "Signature verified against the provided public key."
        : "Signature does not match this document and public key.";
    $("resKeySize").textContent = r.key_size > 0 ? r.key_size + " bits" : "unknown";

    const banner = $("accessBanner");
    banner.classList.remove("hidden");
    if (valid) {
        banner.className = "access granted";
        $("accessTitle").textContent = "ACCESS GRANTED";
        $("accessMsg").textContent = "Authentic document — matches the public key.";
    } else {
        banner.className = "access denied";
        $("accessTitle").textContent = "ACCESS DENIED";
        $("accessMsg").textContent = "Signature does not match — document is not trusted.";
    }

    $("riskScore").textContent = r.risk_score;
    $("threatLevel").textContent = r.threat_level;
    $("attackCategory").textContent = r.attack_category;
    $("assessment").textContent = r.assessment;

    const risk = Number(r.risk_score);
    const safe = Number.isFinite(risk) ? Math.max(0, Math.min(100, risk)) : 0;
    $("riskText").textContent = `${safe} / 100`;
    $("riskFill").style.width = `${safe}%`;

    $("result").classList.remove("hidden");
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showError(msg) {
    errorBox.textContent = "ERROR: " + msg;
    errorBox.classList.remove("hidden");
}
function hideError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
}
