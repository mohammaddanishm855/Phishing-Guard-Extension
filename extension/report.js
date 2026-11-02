
function setText(id, value) {
    document.getElementById(id).textContent = value ?? "Not available";
}

function addFinding(container, title, description) {
    const item = document.createElement("div");
    item.className = "finding-item";

    const heading = document.createElement("strong");
    heading.textContent = title;

    const detail = document.createElement("p");
    detail.textContent = description;

    item.append(heading, detail);
    container.appendChild(item);
}

function addListItem(container, value) {
    const item = document.createElement("li");
    item.textContent = value;
    container.appendChild(item);
}

function getRecommendations(level) {
    if (level === "HIGH") {
        return [
            "Do not enter passwords, payment details, or other sensitive information.",
            "Avoid downloading files from this website.",
            "Close the page and verify the domain through a trusted source."
        ];
    }

    if (level === "MEDIUM") {
        return [
            "Avoid entering sensitive information until the domain is independently verified.",
            "Check the spelling and legitimacy of the website domain.",
            "Access the official website directly rather than through an unexpected link."
        ];
    }

    return [
        "No obvious URL indicators were detected by this scan.",
        "Still verify the domain independently before sharing sensitive information."
    ];
}

async function loadReport() {
    const findingsBox = document.getElementById("findings");
    const recommendationsBox = document.getElementById("recommendations");
    const limitationsBox = document.getElementById("limitations");

    try {
        const stored = await chrome.storage.session.get("latestWebsiteReport");
        const report = stored.latestWebsiteReport;

        if (!report || !report.data) {
            setText("websiteName", "No scan result available");
            setText("verdict", "Please scan a website first");
            findingsBox.textContent = "No website scan data was found.";
            return;
        }

        const data = report.data;
        const level = String(data.risk_level || "UNKNOWN").toUpperCase();

        setText("websiteName", data.hostname || "Unknown website");
        setText("websiteUrl", data.url || "URL unavailable");
        setText("scanTime", `Scanned: ${report.scanTime || "Time unavailable"}`);
        setText("riskScore", data.risk_score ?? "--");
        setText("riskBadge", level);
        setText("verdict", data.verdict || "Assessment unavailable");
        setText("indicatorCount", data.indicator_count ?? 0);
        setText("sensitiveCount", (data.matched_sensitive_terms || []).length);
        setText("brandCount", (data.possible_brand_impersonation || []).length);
        setText("detectionMethod", data.detection_method || "Not specified");

        const riskCard = document.querySelector(".risk-card");
        riskCard.classList.remove("risk-low", "risk-medium", "risk-high");
        riskCard.classList.add(
            level === "HIGH" ? "risk-high" :
            level === "MEDIUM" ? "risk-medium" : "risk-low"
        );

        const descriptions = {
            LOW: "No obvious heuristic indicators were detected. This does not guarantee that the website is safe.",
            MEDIUM: "Potentially suspicious indicators were found. Verify the website before sharing sensitive information.",
            HIGH: "High-risk indicators were detected. Avoid interacting with the website until it has been independently verified."
        };

        setText(
            "riskDescription",
            descriptions[level] || "The scan returned an assessment that requires further review."
        );

        findingsBox.replaceChildren();

        const indicators = Array.isArray(data.risk_indicators)
            ? data.risk_indicators
            : [];

        if (indicators.length > 0) {
            indicators.forEach((indicator, index) => {
                addFinding(
                    findingsBox,
                    `Indicator ${index + 1}`,
                    String(indicator)
                );
            });
        } else {
            findingsBox.textContent =
                "No obvious URL indicators were detected by this heuristic scan.";
        }

        recommendationsBox.replaceChildren();
        getRecommendations(level).forEach(recommendation => {
            const item = document.createElement("div");
            item.className = "recommendation-item";
            item.textContent = recommendation;
            recommendationsBox.appendChild(item);
        });

        limitationsBox.replaceChildren();

        const limitations = Array.isArray(data.limitations)
            ? data.limitations
            : [];

        if (limitations.length > 0) {
            limitations.forEach(item => addListItem(limitationsBox, String(item)));
        } else {
            addListItem(
                limitationsBox,
                "This is an automated heuristic assessment, not a guarantee of website safety."
            );
        }

    } catch (error) {
        findingsBox.textContent = `Unable to load report: ${error.message}`;
    }
}

loadReport();
