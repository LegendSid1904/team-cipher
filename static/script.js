"use strict";

const API_BASE = ""; // same origin

const $ = (id) => document.getElementById(id);

const documentInput = $("documentInput");
const signatureInput = $("signatureInput");
const publicKeyInput = $("publicKeyInput");
const analyzeBtn = $("analyzeBtn");
const loading = $("loading");
const errorBox = $("errorBox");
const results = $("results");

// ---------------------------------------------------------------
// Health
// ---------------------------------------------------------------
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        $("statusText").textContent = data.status === "healthy" ? "ONLINE" : "DEGRADED";
        $("healthStatus").className = "status " + (data.status === "healthy" ? "ok" : "warn");
    } catch (e) {
        $("statusText").textContent = "OFFLINE";
        $("healthStatus").className = "status bad";
    }
}

// ---------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------
analyzeBtn.addEventListener("click", async () => {
    hideError();

    const documentFile = documentInput.files[0];
    const signatureFile = signatureInput.files[0];
    const publicKeyFile = publicKeyInput.files[0];

    if (!documentFile) return showError("Please select the document file.");
    if (!signatureFile) return showError("Please select the signature file.");
    if (!publicKeyFile) return showError("Please select the public key file.");

    const formData = new FormData();
    formData.append("document", documentFile);
    formData.append("signature", signatureFile);
    formData.append("public_key", publicKeyFile);

    analyzeBtn.disabled = true;
    loading.classList.remove("hidden");
    results.classList.add("hidden");

    try {
        const res = await fetch(`${API_BASE}/api/verify`, { method: "POST", body: formData });
        const data = await res.json().catch(() => null);

        if (!res.ok || !data || data.success !== true) {
            const detail = data && data.detail ? data.detail : "Backend request failed.";
            throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
        }

        displayResult(data.result);
        loadEvents();
    } catch (err) {
        showError(err.message);
    } finally {
        analyzeBtn.disabled = false;
        loading.classList.add("hidden");
    }
});

// ---------------------------------------------------------------
// Display result
// ---------------------------------------------------------------
function displayResult(r) {
    const valid = r.signature_verification === "VALID";

    $("signatureVerification").textContent = r.signature_verification;
    $("signatureVerification").className = "auth-status " + (valid ? "ok" : "bad");
    $("authIcon").textContent = valid ? "✓" : "✕";
    $("authIcon").className = "auth-icon " + (valid ? "ok" : "bad");
    $("keySize").textContent = r.key_size > 0 ? r.key_size + " bits" : "unknown";

    $("riskScore").textContent = r.risk_score;
    $("threatLevel").textContent = r.threat_level;
    $("attackCategory").textContent = r.attack_category;
    $("assessment").textContent = r.assessment;

    const risk = Number(r.risk_score);
    const safe = Number.isFinite(risk) ? Math.max(0, Math.min(100, risk)) : 0;
    $("riskText").textContent = `${safe} / 100`;
    $("riskFill").style.width = `${safe}%`;

    populateList("indicators", r.contributing_indicators);
    populateList("explanation", r.assessment_explanation);
    populateList("recommendations", r.recommended_action);

    results.classList.remove("hidden");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function populateList(id, items) {
    const list = $(id);
    list.innerHTML = "";
    if (!Array.isArray(items) || items.length === 0) {
        const li = document.createElement("li");
        li.textContent = "None detected.";
        li.className = "muted";
        list.appendChild(li);
        return;
    }
    items.forEach((text) => {
        const li = document.createElement("li");
        li.textContent = text;
        list.appendChild(li);
    });
}

// ---------------------------------------------------------------
// Events dashboard
// ---------------------------------------------------------------
async function loadEvents() {
    const tbody = $("eventsBody");
    try {
        const res = await fetch(`${API_BASE}/api/events`);
        const data = await res.json();
        const events = data.events || [];

        if (!events.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="muted">No events yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map((e) => `
            <tr>
                <td>${escapeHtml(shortDate(e.timestamp))}</td>
                <td>${escapeHtml(e.filename)}</td>
                <td class="${e.verification === "VALID" ? "ok" : "bad"}">${escapeHtml(e.verification)}</td>
                <td>${escapeHtml(e.risk_score)}</td>
                <td class="${levelClass(e.threat_level)}">${escapeHtml(e.threat_level)}</td>
                <td>${escapeHtml(e.attack_category)}</td>
            </tr>
        `).join("");
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="muted">Could not load events.</td></tr>`;
    }
}

function shortDate(iso) {
    if (!iso) return "–";
    try {
        const d = new Date(iso);
        return d.toLocaleString();
    } catch (e) {
        return String(iso);
    }
}

function levelClass(level) {
    if (level === "HIGH") return "bad";
    if (level === "MEDIUM") return "warn";
    return "ok";
}

function escapeHtml(str) {
    return String(str == null ? "" : str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------
// Errors
// ---------------------------------------------------------------
function showError(msg) {
    errorBox.textContent = "ERROR: " + msg;
    errorBox.classList.remove("hidden");
}
function hideError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
}

// init
checkHealth();
loadEvents();
