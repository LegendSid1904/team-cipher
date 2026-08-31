"use strict";

const $ = (id) => document.getElementById(id);

async function checkHealth() {
    try {
        const res = await fetch(`/api/health`);
        const data = await res.json();
        $("statusText").textContent = data.status === "healthy" ? "ONLINE" : "DEGRADED";
        $("healthStatus").className = "status " + (data.status === "healthy" ? "ok" : "warn");
    } catch (e) {
        $("statusText").textContent = "OFFLINE";
        $("healthStatus").className = "status bad";
    }
}

async function loadEvents() {
    const tbody = $("eventsBody");
    if (!tbody) return;
    try {
        const res = await fetch(`/api/events`);
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
    try { return new Date(iso).toLocaleString(); }
    catch (e) { return String(iso); }
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

checkHealth();
loadEvents();
