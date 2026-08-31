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
wireFileField("privateKeyInput", "boxPrivateKey");

const signBtn = $("signBtn");
const loading = $("loading");
const errorBox = $("errorBox");

signBtn.addEventListener("click", async () => {
    hideError();

    const doc = $("documentInput").files[0];
    const label = $("labelInput").value.trim();
    const name = $("nameInput").value.trim();
    const priv = $("privateKeyInput").files[0];

    if (!doc) return showError("Select the document to sign.");
    if (!label) return showError("Enter a signer label (e.g. alice).");

    const formData = new FormData();
    formData.append("document", doc);
    formData.append("label", label);
    if (name) formData.append("name", name);
    if (priv) formData.append("private_key", priv);

    signBtn.disabled = true;
    loading.classList.remove("hidden");
    $("result").classList.add("hidden");

    try {
        const res = await fetch(`/api/sign`, { method: "POST", body: formData });
        const data = await res.json().catch(() => null);

        if (!res.ok || !data || data.success !== true) {
            const detail = data && data.detail ? data.detail : "Sign request failed.";
            throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
        }

        showResult(data);
        loadKeys();
    } catch (err) {
        showError(err.message);
    } finally {
        signBtn.disabled = false;
        loading.classList.add("hidden");
    }
});

let lastSignatureB64 = null;
let lastPrivateB64 = null;
let lastPublicKey = null;

function showResult(data) {
    lastSignatureB64 = data.signature_b64 || null;
    lastPrivateB64 = data.private_key_b64 || null;
    lastPublicKey = data.public_key || null;

    $("resLabel").textContent = data.label;
    $("resKeySize").textContent = data.key_size ? data.key_size + " bits" : "–";
    $("resNewKey").textContent = data.new_key ? "generated" : "existing";
    $("resSigSize").textContent = lastSignatureB64
        ? Math.round((lastSignatureB64.length * 3) / 4) + " bytes"
        : "–";
    $("resPublicKey").value = lastPublicKey || "";

    $("copyKeyBtn").textContent = "Copy";
    $("downloadKeyBtn").classList.toggle("hidden", !lastPrivateB64);
    $("result").classList.remove("hidden");
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("copyKeyBtn").addEventListener("click", async () => {
    if (!lastPublicKey) return;
    try {
        await navigator.clipboard.writeText(lastPublicKey);
        $("copyKeyBtn").textContent = "Copied ✓";
        setTimeout(() => ( $("copyKeyBtn").textContent = "Copy"), 1500);
    } catch (e) {
        $("resPublicKey").select();
        document.execCommand("copy");
        $("copyKeyBtn").textContent = "Copied ✓";
        setTimeout(() => ( $("copyKeyBtn").textContent = "Copy"), 1500);
    }
});

$("downloadSigBtn").addEventListener("click", () => {
    if (!lastSignatureB64) return;
    downloadBase64(lastSignatureB64, "signature.sig", "application/octet-stream");
});

$("downloadKeyBtn").addEventListener("click", () => {
    if (!lastPrivateB64) return;
    downloadBase64(lastPrivateB64, "private_key.pem", "application/x-pem-file");
});

function downloadBase64(b64, filename, mime) {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadKeys() {
    const tbody = $("keysBody");
    try {
        const res = await fetch(`/api/keys`);
        const data = await res.json();
        const keys = data.keys || [];
        if (!keys.length) {
            tbody.innerHTML = `<tr><td colspan="4" class="muted">No keys registered yet.</td></tr>`;
            return;
        }
        tbody.innerHTML = keys.map((k) => `
            <tr>
                <td><strong>${escapeHtml(k.label)}</strong></td>
                <td>${escapeHtml(k.name || "–")}</td>
                <td>${escapeHtml(k.key_size > 0 ? k.key_size + " bits" : "–")}</td>
                <td>${escapeHtml(shortDate(k.created))}</td>
            </tr>
        `).join("");
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="4" class="muted">Could not load keys.</td></tr>`;
    }
}

function shortDate(iso) {
    if (!iso) return "–";
    try { return new Date(iso).toLocaleString(); }
    catch (e) { return String(iso); }
}

function escapeHtml(str) {
    return String(str == null ? "" : str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function showError(msg) {
    errorBox.textContent = "ERROR: " + msg;
    errorBox.classList.remove("hidden");
}
function hideError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
}

loadKeys();
