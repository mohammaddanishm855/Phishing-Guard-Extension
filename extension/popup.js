
const API = "http://127.0.0.1:8000";

const tabs = document.querySelectorAll(".tab");
const sections = document.querySelectorAll(".section");

// Switch scanner tabs
tabs.forEach(tab => {
    tab.addEventListener("click", () => {
        tabs.forEach(item => item.classList.remove("active"));
        sections.forEach(item => item.classList.remove("active"));

        tab.classList.add("active");

        document.getElementById(tab.dataset.section)
            .classList.add("active");
    });
});

// Backend connection check
async function checkBackend() {
    const status = document.getElementById("connectionStatus");
    const dot = document.querySelector(".status-dot");

    try {
        const response = await fetch(`${API}/health`);

        if (!response.ok) {
            throw new Error("Backend unavailable");
        }

        const data = await response.json();
        const connected = data.status === "healthy";

        status.textContent = connected
            ? "Backend Connected"
            : "Backend Status Unknown";

        dot.style.background = connected ? "#34d399" : "#fbbf24";

    } catch {
        status.textContent = "Backend Disconnected";
        dot.style.background = "#fb7185";
    }
}

// Display results
function displayResult(elementId, data) {
    const box = document.getElementById(elementId);

    box.classList.remove("hidden");
    box.textContent = JSON.stringify(data, null, 2);
}

// Display errors
function showError(elementId, message) {
    const box = document.getElementById(elementId);

    box.classList.remove("hidden");
    box.textContent = message;
}

// Save scan result and open HTML security report
async function openWebsiteReport(data) {
    await chrome.storage.session.set({
        latestWebsiteReport: {
            data: data,
            scanTime: new Date().toLocaleString()
        }
    });

    await chrome.tabs.create({
        url: chrome.runtime.getURL("report.html")
    });
}

// Website scanning
async function scanWebsite(url) {
    const button = document.getElementById("scanUrlBtn");

    button.disabled = true;
    button.textContent = "Analyzing Website...";

    try {
        const response = await fetch(`${API}/scan/url`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Website scan failed.");
        }

        await openWebsiteReport(data);

    } catch (error) {
        showError("urlResult", `Scan error: ${error.message}`);
    } finally {
        button.disabled = false;
        button.textContent = "Scan Website";
    }
}

// Detect current website and fill URL input only
async function detectCurrentWebsite() {
    const input = document.getElementById("urlInput");

    try {
        const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (!tab || !tab.url) {
            throw new Error("Unable to detect the current tab.");
        }

        const url = new URL(tab.url);

        if (!["http:", "https:"].includes(url.protocol)) {
            input.value = "";
            showError(
                "urlResult",
                "This browser page cannot be scanned. Open a normal HTTP or HTTPS website."
            );
            return;
        }

        input.value = tab.url;

    } catch (error) {
        showError("urlResult", error.message);
    }
}

// Manual website scan
document.getElementById("scanUrlBtn").addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value.trim();

    if (!url) {
        showError("urlResult", "Please enter a website URL.");
        return;
    }

    await scanWebsite(url);
});

// Email scanning
document.getElementById("scanEmailBtn").addEventListener("click", async () => {
    const button = document.getElementById("scanEmailBtn");
    const email = document.getElementById("emailInput").value.trim();

    if (!email) {
        showError("emailResult", "Please paste an email before scanning.");
        return;
    }

    button.disabled = true;
    button.textContent = "Analyzing Email...";

    try {
        const response = await fetch(`${API}/scan/email`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email_content: email })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Email scan failed.");
        }

        displayResult("emailResult", data);

    } catch (error) {
        showError("emailResult", `Scan error: ${error.message}`);
    } finally {
        button.disabled = false;
        button.textContent = "Scan Email";
    }
});

// Attachment scanning - backend integration pending
document.getElementById("scanFileBtn").addEventListener("click", () => {
    showError(
        "fileResult",
        "Attachment scanning is not connected yet."
    );
});

// Initialize popup without automatically scanning
async function initializeExtension() {
    await checkBackend();
    await detectCurrentWebsite();
}

initializeExtension();
