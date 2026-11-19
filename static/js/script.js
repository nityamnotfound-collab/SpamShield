// Shared page IDs: site-nav, menu-toggle, theme-toggle.
function getElement(elementId) {
    return document.getElementById(elementId);
}

// Keep the theme control and mobile navigation safe to use on every page.
const siteNavigation = getElement("site-nav");
const menuToggle = getElement("menu-toggle");
const themeToggle = getElement("theme-toggle");

if (menuToggle && siteNavigation) {
    const menuIcon = menuToggle.querySelector("i");

    menuToggle.addEventListener("click", () => {
        const isOpen = siteNavigation.classList.toggle("is-open");
        menuToggle.setAttribute("aria-expanded", String(isOpen));
        menuToggle.setAttribute(
            "aria-label",
            isOpen ? "Close navigation menu" : "Open navigation menu"
        );

        if (menuIcon) {
            menuIcon.className = isOpen
                ? "fa-solid fa-xmark"
                : "fa-solid fa-bars";
        }
    });

    siteNavigation.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => {
            siteNavigation.classList.remove("is-open");
            menuToggle.setAttribute("aria-expanded", "false");
        });
    });
}

function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    if (!themeToggle) {
        return;
    }

    const themeIcon = themeToggle.querySelector("i");
    const isDark = theme === "dark";
    themeToggle.setAttribute(
        "aria-label",
        isDark ? "Switch to light theme" : "Switch to dark theme"
    );

    if (themeIcon) {
        themeIcon.className = isDark
            ? "fa-solid fa-sun"
            : "fa-solid fa-moon";
    }
}

let savedTheme = "dark";
try {
    const storedTheme = localStorage.getItem("spamshield-theme");
    if (storedTheme === "light" || storedTheme === "dark") {
        savedTheme = storedTheme;
    }
} catch (error) {
    // The default theme still works when browser storage is unavailable.
}
applyTheme(savedTheme);

if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        const nextTheme =
            document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        applyTheme(nextTheme);
        try {
            localStorage.setItem("spamshield-theme", nextTheme);
        } catch (error) {
            // Theme switching remains available for the current page.
        }
    });
}

// Write list content with textContent so submitted text is never interpreted as HTML.
function fillList(listElement, values, emptyMessage) {
    if (!listElement) {
        return;
    }

    listElement.replaceChildren();
    if (!Array.isArray(values) || values.length === 0) {
        const item = document.createElement("li");
        item.textContent = emptyMessage;
        listElement.appendChild(item);
        return;
    }

    values.forEach((value) => {
        const item = document.createElement("li");
        item.textContent = String(value);
        listElement.appendChild(item);
    });
}

function setBadge(badge, classification) {
    if (!badge) {
        return;
    }
    const safeClassification = String(classification || "UNKNOWN");
    badge.textContent = safeClassification;
    badge.className = "classification-badge " +
        safeClassification.toLowerCase().replace(/\s+/g, "-");
}

function showFriendlyError(errorElement, message) {
    if (!errorElement) {
        return;
    }
    errorElement.textContent = message;
    errorElement.hidden = false;
}

function downloadTextFile(fileName, text, mimeType) {
    const file = new Blob([text], { type: mimeType });
    const fileUrl = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = fileUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(fileUrl), 1000);
}

// Dashboard: load real database counts and the latest saved scans.
const dashboardPage = getElement("dashboard-page");
if (dashboardPage) {
    let dashboardChart = null;

    async function loadDashboard() {
        const errorElement = getElement("dashboard-error");
        try {
            const response = await fetch("/api/dashboard-stats");
            const stats = await response.json();
            if (!response.ok) {
                throw new Error("Dashboard data is unavailable.");
            }

            getElement("total-messages").textContent = stats.messages;
            getElement("safe-count").textContent = stats.safe;
            getElement("spam-count").textContent = stats.spam;
            getElement("suspicious-count").textContent = stats.suspicious;
            getElement("urls-analysed").textContent = stats.urls;
            drawDashboardChart(stats.spam_vs_safe || []);
            renderRecentScans(stats.last_five || []);
            errorElement.hidden = true;
        } catch (error) {
            showFriendlyError(
                errorElement,
                "Dashboard data could not be loaded. Please try again."
            );
        }
    }

    function drawDashboardChart(counts) {
        const canvas = getElement("spam-safe-chart");
        if (!canvas || typeof Chart === "undefined") {
            return;
        }

        const labels = counts.map((item) => item.prediction);
        const values = counts.map((item) => item.count);

        if (dashboardChart) {
            dashboardChart.destroy();
        }

        dashboardChart = new Chart(canvas, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: ["#22c55e", "#ef4444"],
                    borderColor: getComputedStyle(document.documentElement)
                        .getPropertyValue("--card")
                        .trim(),
                    borderWidth: 4,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: getComputedStyle(document.documentElement)
                                .getPropertyValue("--text")
                                .trim(),
                            usePointStyle: true,
                            padding: 18,
                        },
                    },
                },
            },
        });
    }

    function renderRecentScans(scans) {
        const tableBody = getElement("recent-scans-body");
        if (!tableBody) {
            return;
        }

        tableBody.replaceChildren();
        if (scans.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 5;
            cell.textContent = "No scans yet.";
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        scans.forEach((scan) => {
            const row = document.createElement("tr");
            const rowValues = [
                scan.scan_type,
                scan.content,
                scan.prediction,
                scan.score === undefined ? "" : String(scan.score) + "%",
                scan.created_at,
            ];
            rowValues.forEach((value) => {
                const cell = document.createElement("td");
                cell.textContent = value === undefined || value === null
                    ? ""
                    : String(value);
                row.appendChild(cell);
            });
            tableBody.appendChild(row);
        });
    }

    loadDashboard();
}

// Message scanner: validate, submit, and display the model and rule-check results.
const messageForm = getElement("message-form");
if (messageForm) {
    const messageInput = getElement("message-text");
    const messageSource = getElement("message-source");
    const messageError = getElement("message-error");
    const messageResultCard = getElement("message-result");
    const messageSpinner = getElement("message-spinner");
    const analyzeButton = getElement("analyze-message-button");
    let latestMessageResult = null;

    const messageSamples = {
        safe: "Hi, are we still meeting at the library at 3 PM? I can bring the notes.",
        lottery: "Congratulations! You won Rs. 25,000 in our lucky draw. Claim your lottery prize now!",
        banking: "URGENT: Your SBI account will be blocked due to KYC expiry. Verify your account at http://sbi-kyc-update.example",
        otp: "Send me the OTP you just received to release your cashback reward immediately.",
        job: "Work from home job offer! Earn Rs. 5,000 daily. Pay a registration fee and send your bank details now.",
    };

    function updateMessageCounter() {
        getElement("message-char-count").textContent =
            messageInput.value.length + " / 5000";
    }

    function makeMessageReportText(result) {
        return [
            "SpamShield Message Estimate",
            "Classification: " + result.classification,
            "ML prediction: " + result.ml_prediction,
            "Spam probability: " + result.confidence + "%",
            "Risk level: " + result.risk_level,
            "Explanation:",
            ...(result.explanation || []).map((item) => "- " + item),
            "Suspicious keywords:",
            ...(result.suspicious_keywords || []).map((item) => "- " + item),
            "Supplementary security checks (separate from ML prediction):",
            ...(result.supplementary_checks || []).map((item) => "- " + item),
            "Recommended action: " + result.recommended_action,
            "Results are estimates. Independently verify suspicious messages.",
        ].join("\n");
    }

    function renderMessageResult(result) {
        setBadge(getElement("message-classification"), result.classification);

        const confidence = Math.max(
            0,
            Math.min(100, Number(result.confidence) || 0)
        );
        getElement("message-confidence-value").textContent =
            confidence.toFixed(2) + "%";
        const confidenceBar = getElement("message-confidence-bar");
        confidenceBar.style.width = confidence + "%";
        confidenceBar.parentElement.setAttribute("aria-valuenow", confidence);

        getElement("message-risk-level").textContent = result.risk_level || "";
        fillList(
            getElement("message-explanations"),
            result.explanation,
            "No explanation details were returned."
        );
        fillList(
            getElement("message-keywords"),
            result.suspicious_keywords,
            "No suspicious keywords were detected."
        );

        const checkLabels = Array.isArray(result.supplementary_checks)
            ? result.supplementary_checks.map((check) =>
                String(check).replace(/_/g, " ")
            )
            : [];
        fillList(
            getElement("supplementary-checks-list"),
            checkLabels,
            "No supplementary rule checks were triggered."
        );
        getElement("recommended-action").textContent =
            result.recommended_action || "";
        getElement("message-action-feedback").textContent = "";
        messageResultCard.hidden = false;
    }

    messageInput.addEventListener("input", updateMessageCounter);
    document.querySelectorAll("#sample-buttons [data-sample]").forEach((button) => {
        button.addEventListener("click", () => {
            const sample = messageSamples[button.dataset.sample];
            if (sample) {
                messageInput.value = sample;
                updateMessageCounter();
                messageInput.focus();
            }
        });
    });

    messageForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        messageError.hidden = true;
        messageResultCard.hidden = true;

        const message = messageInput.value.trim();
        if (!message) {
            showFriendlyError(messageError, "Enter a message to analyze.");
            return;
        }
        if (message.length > 5000) {
            showFriendlyError(messageError, "Messages can contain up to 5000 characters.");
            return;
        }

        analyzeButton.disabled = true;
        messageSpinner.hidden = false;
        try {
            const response = await fetch("/api/analyze-message", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    message: message,
                    source: messageSource.value,
                }),
            });
            const result = await response.json();
            if (!response.ok) {
                showFriendlyError(
                    messageError,
                    result.error || "Message analysis failed. Please try again."
                );
                return;
            }

            latestMessageResult = result;
            renderMessageResult(result);
        } catch (error) {
            showFriendlyError(
                messageError,
                "Message analysis is unavailable right now. Please try again."
            );
        } finally {
            analyzeButton.disabled = false;
            messageSpinner.hidden = true;
        }
    });

    const copyButton = getElement("copy-message-result");
    if (copyButton) {
        copyButton.addEventListener("click", async () => {
            if (!latestMessageResult) {
                return;
            }

            const feedback = getElement("message-action-feedback");
            try {
                await navigator.clipboard.writeText(
                    makeMessageReportText(latestMessageResult)
                );
                feedback.textContent = "Result copied.";
            } catch (error) {
                feedback.textContent = "Copy is unavailable in this browser.";
            }
        });
    }

    const downloadButton = getElement("download-message-report");
    if (downloadButton) {
        downloadButton.addEventListener("click", async () => {
            if (!latestMessageResult || latestMessageResult.id === undefined) {
                return;
            }

            const feedback = getElement("message-action-feedback");
            const scanId = String(latestMessageResult.id);
            downloadButton.disabled = true;
            try {
                const response = await fetch(
                    "/api/report/" + encodeURIComponent(scanId)
                );
                const reportData = await response.json();
                if (!response.ok || !reportData.report) {
                    throw new Error("Report is unavailable.");
                }

                downloadTextFile(
                    "spamshield-message-report.json",
                    JSON.stringify(reportData.report, null, 2),
                    "application/json"
                );
                feedback.textContent = "Report downloaded.";
            } catch (error) {
                feedback.textContent = "Report could not be downloaded. Please try again.";
            } finally {
                downloadButton.disabled = false;
            }
        });
    }

    updateMessageCounter();
}

// URL scanner: send URL text only; this code never navigates to the submitted URL.
const urlForm = getElement("url-form");
if (urlForm) {
    const urlInput = getElement("url-text");
    const urlError = getElement("url-error");
    const urlResultCard = getElement("url-result");
    const urlSpinner = getElement("url-spinner");
    const checkUrlButton = getElement("check-url-button");

    urlInput.addEventListener("input", () => {
        getElement("url-char-count").textContent =
            urlInput.value.length + " / 2000";
    });

    urlForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        urlError.hidden = true;
        urlResultCard.hidden = true;

        const urlText = urlInput.value.trim();
        if (!urlText) {
            showFriendlyError(urlError, "Enter a URL to check.");
            return;
        }
        if (urlText.length > 2000) {
            showFriendlyError(urlError, "URLs can contain up to 2000 characters.");
            return;
        }

        checkUrlButton.disabled = true;
        urlSpinner.hidden = false;
        try {
            const response = await fetch("/api/analyze-url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlText }),
            });
            const result = await response.json();
            if (!response.ok) {
                showFriendlyError(
                    urlError,
                    result.error || "URL check failed. Please try again."
                );
                return;
            }

            setBadge(getElement("url-classification"), result.classification);
            const riskScore = Math.max(
                0,
                Math.min(100, Number(result.risk_score) || 0)
            );
            getElement("url-risk-score").textContent = riskScore + " / 100";
            const riskBar = getElement("url-risk-bar");
            riskBar.style.width = riskScore + "%";
            riskBar.parentElement.setAttribute("aria-valuenow", riskScore);
            fillList(
                getElement("url-reasons"),
                result.reasons,
                "No suspicious URL patterns were detected."
            );
            getElement("url-recommendation").textContent =
                result.recommendation || "";
            getElement("url-note").textContent =
                (result.note || "This is a pattern-based check, not a threat-database lookup.") +
                " The URL is not opened or visited.";
            urlResultCard.hidden = false;
        } catch (error) {
            showFriendlyError(
                urlError,
                "URL check is unavailable right now. Please try again."
            );
        } finally {
            checkUrlButton.disabled = false;
            urlSpinner.hidden = true;
        }
    });
}

// History: query, view, and delete records using string IDs.
const historyPage = getElement("history-page");
if (historyPage) {
    const searchInput = getElement("history-search");
    const typeFilter = getElement("history-type-filter");
    const classificationFilter = getElement("history-classification-filter");
    const tableBody = getElement("history-table-body");
    const emptyMessage = getElement("history-empty");
    const historyError = getElement("history-error");
    const detailsDialog = getElement("history-details-modal");
    let searchTimer = null;

    async function loadHistory() {
        historyError.hidden = true;
        const query = new URLSearchParams();
        if (searchInput.value.trim()) {
            query.set("search", searchInput.value.trim());
        }
        if (typeFilter.value) {
            query.set("scan_type", typeFilter.value);
        }
        if (classificationFilter.value) {
            query.set("prediction", classificationFilter.value);
        }

        const queryString = query.toString();
        const endpoint = queryString
            ? "/api/history?" + queryString
            : "/api/history";
        try {
            const response = await fetch(endpoint);
            const data = await response.json();
            if (!response.ok) {
                throw new Error("History could not be loaded.");
            }
            renderHistoryRows(data.history || []);
        } catch (error) {
            tableBody.replaceChildren();
            emptyMessage.hidden = true;
            showFriendlyError(
                historyError,
                "History is unavailable right now. Please try again."
            );
        }
    }

    function renderHistoryRows(scans) {
        tableBody.replaceChildren();
        emptyMessage.hidden = scans.length > 0;

        scans.forEach((scan) => {
            const scanId = String(scan.id);
            const row = document.createElement("tr");

            const contentCell = document.createElement("td");
            contentCell.className = "history-preview";
            contentCell.textContent = scan.content || "";
            contentCell.title = scan.content || "";
            row.appendChild(contentCell);

            const typeCell = document.createElement("td");
            typeCell.textContent = scan.scan_type || "";
            row.appendChild(typeCell);

            const classificationCell = document.createElement("td");
            const badge = document.createElement("span");
            setBadge(badge, scan.prediction);
            classificationCell.appendChild(badge);
            row.appendChild(classificationCell);

            const scoreCell = document.createElement("td");
            scoreCell.textContent = String(scan.score) + "%";
            row.appendChild(scoreCell);

            const dateCell = document.createElement("td");
            dateCell.textContent = scan.created_at || "";
            row.appendChild(dateCell);

            const actionsCell = document.createElement("td");
            const actions = document.createElement("div");
            actions.className = "history-actions";
            const viewButton = document.createElement("button");
            viewButton.className = "small-action-button";
            viewButton.type = "button";
            viewButton.textContent = "View";
            viewButton.addEventListener("click", () => showScanDetails(scanId));

            const deleteButton = document.createElement("button");
            deleteButton.className = "small-action-button delete-scan";
            deleteButton.type = "button";
            deleteButton.textContent = "Delete";
            deleteButton.addEventListener("click", () => deleteOneScan(scanId));

            actions.append(viewButton, deleteButton);
            actionsCell.appendChild(actions);
            row.appendChild(actionsCell);
            tableBody.appendChild(row);
        });
    }

    function appendDetail(detailsElement, label, value) {
        const row = document.createElement("div");
        row.className = "detail-row";
        const heading = document.createElement("strong");
        heading.textContent = label;
        const text = document.createElement("p");
        text.textContent = Array.isArray(value)
            ? value.join("\n")
            : value === undefined || value === null ? "" : String(value);
        row.append(heading, text);
        detailsElement.appendChild(row);
    }

    async function showScanDetails(scanId) {
        historyError.hidden = true;
        try {
            const response = await fetch(
                "/api/history/" + encodeURIComponent(String(scanId))
            );
            const scan = await response.json();
            if (!response.ok) {
                throw new Error("Scan details could not be loaded.");
            }

            const detailsElement = getElement("history-details-content");
            detailsElement.replaceChildren();
            appendDetail(detailsElement, "Type", scan.scan_type);
            appendDetail(detailsElement, "Source", scan.source);
            appendDetail(detailsElement, "Classification", scan.prediction);
            appendDetail(detailsElement, "Score", String(scan.score) + "%");
            appendDetail(detailsElement, "Date and time", scan.created_at);
            appendDetail(detailsElement, "Content", scan.content);
            appendDetail(detailsElement, "Explanation", scan.explanation);
            appendDetail(detailsElement, "Flags", scan.flags);
            detailsDialog.showModal();
        } catch (error) {
            showFriendlyError(
                historyError,
                "Scan details are unavailable right now. Please try again."
            );
        }
    }

    async function deleteOneScan(scanId) {
        if (!window.confirm("Delete this scan from history?")) {
            return;
        }

        try {
            const response = await fetch(
                "/api/history/" + encodeURIComponent(String(scanId)),
                { method: "DELETE" }
            );
            if (!response.ok) {
                throw new Error("Scan could not be deleted.");
            }
            await loadHistory();
        } catch (error) {
            showFriendlyError(
                historyError,
                "The scan could not be deleted. Please try again."
            );
        }
    }

    searchInput.addEventListener("input", () => {
        window.clearTimeout(searchTimer);
        searchTimer = window.setTimeout(loadHistory, 250);
    });
    typeFilter.addEventListener("change", loadHistory);
    classificationFilter.addEventListener("change", loadHistory);

    getElement("clear-history-button").addEventListener("click", async () => {
        if (!window.confirm("Clear all scan history? This cannot be undone.")) {
            return;
        }

        historyError.hidden = true;
        try {
            const response = await fetch("/api/history", { method: "DELETE" });
            if (!response.ok) {
                throw new Error("History could not be cleared.");
            }
            await loadHistory();
        } catch (error) {
            showFriendlyError(
                historyError,
                "History could not be cleared. Please try again."
            );
        }
    });

    getElement("close-history-details").addEventListener("click", () => {
        detailsDialog.close();
    });
    detailsDialog.addEventListener("click", (event) => {
        if (event.target === detailsDialog) {
            detailsDialog.close();
        }
    });

    loadHistory();
}
