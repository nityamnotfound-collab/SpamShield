// Shared page IDs: site-nav, menu-toggle, main-content.
function getElement(elementId) {
    return document.getElementById(elementId);
}

const siteNavigation = getElement("site-nav");
const menuToggle = getElement("menu-toggle");
const appScrim = document.querySelector("[data-close-sidebar]");

if (menuToggle && siteNavigation) {
    const menuIcon = menuToggle.querySelector("i");

    menuToggle.addEventListener("click", () => {
        const isOpen = siteNavigation.classList.toggle("is-open");
        document.body.classList.toggle("sidebar-open", isOpen);
        if (appScrim) {
            appScrim.hidden = !isOpen;
        }
        menuToggle.setAttribute("aria-expanded", String(isOpen));
        menuToggle.setAttribute(
            "aria-label",
            t(isOpen ? "Close navigation menu" : "Open navigation menu")
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
            document.body.classList.remove("sidebar-open");
            if (appScrim) {
                appScrim.hidden = true;
            }
            menuToggle.setAttribute("aria-expanded", "false");
            menuToggle.setAttribute("aria-label", t("Open navigation menu"));
        });
    });
}

if (appScrim && menuToggle && siteNavigation) {
    appScrim.addEventListener("click", () => {
        siteNavigation.classList.remove("is-open");
        document.body.classList.remove("sidebar-open");
        appScrim.hidden = true;
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.setAttribute("aria-label", t("Open navigation menu"));
        const menuIcon = menuToggle.querySelector("i");
        if (menuIcon) {
            menuIcon.className = "fa-solid fa-bars";
        }
    });
}

const fontSizeButtons = document.querySelectorAll("[data-font-size]");
if (fontSizeButtons.length) {
    fontSizeButtons.forEach((button) => {
        button.addEventListener("click", () => {
            document.documentElement.style.fontSize =
                button.getAttribute("data-font-size") + "px";
        });
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
    const result = String(classification || "UNKNOWN").trim().toUpperCase();
    const statuses = {
        SAFE: ["safe", "fa-circle-check", t("SAFE")],
        SPAM: ["spam", "fa-circle-xmark", t("SPAM")],
        SUSPICIOUS: ["suspicious", "fa-triangle-exclamation", t("SUSPICIOUS")],
        "HIGH RISK": ["high-risk", "fa-circle-exclamation", t("HIGH RISK")],
    };
    const status = statuses[result] || [
        "unknown",
        "fa-circle-info",
        result === "UNKNOWN" ? t("Result unavailable") : result,
    ];
    const icon = document.createElement("i");
    icon.className = "fa-solid " + status[1];
    icon.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = status[2];
    badge.replaceChildren(icon, label);
    badge.className = "classification-badge status-badge status-" + status[0];
}

function showFriendlyError(errorElement, message) {
    if (!errorElement) {
        return;
    }
    setRuntimeText(errorElement, message);
    errorElement.hidden = false;
}

function setRuntimeText(element, message) {
    if (!element) {
        return;
    }
    element.dataset.i18nLive = message;
    element.textContent = t(message);
}

window.addEventListener("spamshield:languagechange", () => {
    document.querySelectorAll("[data-i18n-live]").forEach((element) => {
        element.textContent = t(element.dataset.i18nLive);
    });
});

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

const DASHBOARD_UPDATE_CHANNEL = "spamshield-scan-updates";
const dashboardUpdateChannel = typeof BroadcastChannel !== "undefined"
    ? new BroadcastChannel(DASHBOARD_UPDATE_CHANNEL)
    : null;
if (dashboardUpdateChannel) {
    window.addEventListener(
        "pagehide",
        () => dashboardUpdateChannel.close(),
        { once: true }
    );
}

function notifyDashboardDataChanged() {
    window.dispatchEvent(new Event("spamshield:data-changed"));
    if (dashboardUpdateChannel) {
        dashboardUpdateChannel.postMessage("updated");
    }
}

// Dashboard: fetch user-scoped stats and refresh the charts and activity.
const dashboardPage = getElement("dashboard-page");
if (dashboardPage) {
    const rangeSelect = getElement("dashboard-range");
    const refreshButton = getElement("dashboard-refresh");
    const errorElement = getElement("dashboard-error");
    const emptyState = getElement("dashboard-empty");
    const dashboardData = getElement("dashboard-data");
    const detailsDialog = getElement("dashboard-details-modal");
    const detailsError = getElement("dashboard-details-error");
    const charts = {};
    let activeController = null;
    let hasLoaded = false;
    let latestDashboardStats = null;
    let latestDetailsScan = null;

    function dashboardColor(token) {
        return getComputedStyle(document.documentElement)
            .getPropertyValue(token)
            .trim();
    }

    function chartOptions(legendPosition) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: Boolean(legendPosition),
                    position: legendPosition || "top",
                    labels: {
                        color: dashboardColor("--text"),
                        usePointStyle: true,
                        padding: 16,
                    },
                },
            },
            scales: {
                x: {
                    ticks: { color: dashboardColor("--muted") },
                    grid: { color: dashboardColor("--border") },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: dashboardColor("--muted"), precision: 0 },
                    grid: { color: dashboardColor("--border") },
                },
            },
        };
    }

    function replaceDashboardChart(canvasId, type, data, options) {
        const canvas = getElement(canvasId);
        if (!canvas || typeof Chart === "undefined") {
            return;
        }
        if (charts[canvasId]) {
            charts[canvasId].destroy();
        }
        charts[canvasId] = new Chart(canvas, {
            type: type,
            data: data,
            options: options,
        });
    }

    function formatDate(dateString) {
        const date = new Date(dateString + "T00:00:00");
        return Number.isNaN(date.getTime())
            ? dateString
            : new Intl.DateTimeFormat(
                getCurrentLanguage() === "hi" ? "hi-IN" : "en-IN", {
                month: "short",
                day: "numeric",
                }
            ).format(date);
    }

    function renderScansPerDay(scans) {
        const safe = dashboardColor("--safe");
        const accent = dashboardColor("--accent");
        replaceDashboardChart(
            "scans-per-day-chart",
            "line",
            {
                labels: scans.map((day) => formatDate(day.date)),
                datasets: [
                    {
                        label: t("Messages"),
                        data: scans.map((day) => day.messages),
                        borderColor: accent,
                        backgroundColor: accent,
                        tension: 0.25,
                    },
                    {
                        label: t("URLs"),
                        data: scans.map((day) => day.urls),
                        borderColor: safe,
                        backgroundColor: safe,
                        tension: 0.25,
                    },
                ],
            },
            Object.assign(chartOptions("bottom"), {
                interaction: { intersect: false, mode: "index" },
                scales: {
                    x: Object.assign(chartOptions().scales.x, {
                        ticks: Object.assign(chartOptions().scales.x.ticks, {
                            maxTicksLimit: 10,
                        }),
                    }),
                    y: chartOptions().scales.y,
                },
            })
        );
        getElement("scans-per-day-summary").textContent = scans.length
            ? scans.map((day) => t("{date}: {count}", {
                date: formatDate(day.date),
                count: day.total,
            })).join("; ")
            : t("No scans in this period.");
    }

    function renderResults(stats) {
        const values = [stats.safe, stats.suspicious, stats.spam].map(Number);
        replaceDashboardChart(
            "result-chart",
            "doughnut",
            {
                labels: [t("SAFE"), t("SUSPICIOUS"), t("SPAM")],
                datasets: [{
                    data: values,
                    backgroundColor: [
                        dashboardColor("--safe"),
                        dashboardColor("--warning"),
                        dashboardColor("--danger"),
                    ],
                    borderColor: dashboardColor("--surface"),
                    borderWidth: 3,
                }],
            },
            Object.assign(chartOptions("bottom"), { cutout: "62%" })
        );
        getElement("result-chart-summary").textContent =
            t("SAFE") + ": " + values[0] + "; " + t("SUSPICIOUS") + ": " +
            values[1] + "; " + t("SPAM") + ": " + values[2] + ".";
    }

    function renderSources(sources) {
        const labels = sources.map((item) => t(item.source));
        const values = sources.map((item) => item.count);
        replaceDashboardChart(
            "source-chart",
            "bar",
            {
                labels: labels,
                datasets: [{
                    label: t("Scans"),
                    data: values,
                    backgroundColor: dashboardColor("--accent"),
                    borderRadius: 5,
                }],
            },
            Object.assign(chartOptions(false), {
                indexAxis: "x",
                plugins: { legend: { display: false } },
            })
        );
        getElement("source-chart-summary").textContent = sources.length
            ? sources.map((item) => t("{source}: {count}", {
                source: t(item.source),
                count: item.count,
            })).join("; ")
            : t("No scan sources in this period.");
    }

    function categoryLabel(category) {
        const labels = {
            banking: t("Banking"),
            lottery: t("Lottery"),
            otp: t("OTP"),
            phishing: t("Phishing"),
            fake_job: t("Fake job"),
            delivery: t("Delivery"),
            promotional: t("Promotional"),
        };
        return labels[category] || category;
    }

    function renderCategories(categories) {
        const labels = categories.map((item) => categoryLabel(item.category));
        const values = categories.map((item) => item.count);
        replaceDashboardChart(
            "category-chart",
            "bar",
            {
                labels: labels,
                datasets: [{
                    label: t("Scans"),
                    data: values,
                    backgroundColor: dashboardColor("--warning"),
                    borderRadius: 5,
                }],
            },
            Object.assign(chartOptions(false), {
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: chartOptions().scales.x,
                    y: Object.assign(chartOptions().scales.y, {
                        grid: { display: false },
                    }),
                },
            })
        );
        getElement("category-chart-summary").textContent = categories.length
            ? categories.map((item) => t("{source}: {count}", {
                source: categoryLabel(item.category),
                count: item.count,
            })).join("; ")
            : t("No scam categories in this period.");
    }

    function renderChange(elementId, change, rangeName) {
        const element = getElement(elementId);
        element.classList.remove("is-up", "is-down");
        if (!change || change.percent === null || change.percent === undefined) {
            element.textContent = rangeName === "all"
                ? t("No previous period for all time")
                : t("No previous-period data");
            return;
        }

        const percent = Number(change.percent);
        const icon = document.createElement("i");
        icon.className = percent > 0
            ? "fa-solid fa-arrow-trend-up"
            : percent < 0 ? "fa-solid fa-arrow-trend-down" : "fa-solid fa-minus";
        icon.setAttribute("aria-hidden", "true");
        const label = document.createElement("span");
        label.textContent = t("{percent}% vs previous period", {
            percent: (percent > 0 ? "+" : "") + percent,
        });
        element.replaceChildren(icon, label);
        if (percent > 0) {
            element.classList.add("is-up");
        } else if (percent < 0) {
            element.classList.add("is-down");
        }
    }

    function renderKeywords(keywords) {
        const list = getElement("top-keywords");
        list.replaceChildren();
        if (!keywords.length) {
            const item = document.createElement("li");
            item.textContent = t("No suspicious keywords found in this period.");
            list.appendChild(item);
            return;
        }

        keywords.forEach((entry) => {
            const item = document.createElement("li");
            const row = document.createElement("span");
            row.className = "keyword-row";
            const keyword = document.createElement("strong");
            keyword.textContent = entry.keyword;
            const count = document.createElement("span");
            count.className = "keyword-count";
            count.textContent = t(
                entry.count === 1 ? "{count} scan" : "{count} scans",
                { count: entry.count }
            );
            row.append(keyword, count);
            item.appendChild(row);
            list.appendChild(item);
        });
    }

    function formatTimestamp(value) {
        const date = new Date(String(value).replace(" ", "T") + "Z");
        return Number.isNaN(date.getTime())
            ? String(value || "")
            : new Intl.DateTimeFormat(
                getCurrentLanguage() === "hi" ? "hi-IN" : "en-IN", {
                dateStyle: "medium",
                timeStyle: "short",
                }
            ).format(date);
    }

    async function showDashboardDetails(scanId) {
        detailsError.hidden = true;
        try {
            const response = await fetch(
                "/api/history/" + encodeURIComponent(String(scanId))
            );
            const scan = await response.json();
            if (!response.ok) {
                throw new Error(t("Scan details could not be loaded."));
            }

            latestDetailsScan = scan;
            renderDashboardDetails(scan);
            detailsDialog.showModal();
        } catch (error) {
            showFriendlyError(
                detailsError,
                "Scan details are unavailable right now. Please try again."
            );
            if (!detailsDialog.open) {
                detailsDialog.showModal();
            }
        }
    }

    function renderDashboardDetails(scan) {
        const details = getElement("dashboard-details-content");
        details.replaceChildren();
        [
            [t("Type"), t(scan.scan_type === "url" ? "URL" : "Message")],
            [t("Source"), t(scan.source)],
            [t("Classification"), t(scan.prediction)],
            [t("Score"), String(scan.score) + "%"],
            [t("Date and time"), scan.created_at],
            [t("Content"), scan.content],
            [t("Explanation"), scan.explanation],
            [t("Categories"), (scan.categories || []).map(categoryLabel)],
            [t("Keywords"), scan.keywords],
        ].forEach(([title, value]) => appendDashboardDetail(details, title, value));
    }

    function appendDashboardDetail(container, label, value) {
        const row = document.createElement("div");
        row.className = "detail-row";
        const heading = document.createElement("strong");
        heading.textContent = label;
        const content = document.createElement("p");
        content.textContent = Array.isArray(value)
            ? value.join("\n")
            : value === undefined || value === null ? "" : String(value);
        row.append(heading, content);
        container.appendChild(row);
    }

    function renderRecentScans(scans) {
        const tableBody = getElement("recent-scans-body");
        tableBody.replaceChildren();
        if (!scans.length) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 5;
            cell.textContent = t("No recent scans.");
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        scans.forEach((scan) => {
            const row = document.createElement("tr");
            const type = t(scan.scan_type === "url" ? "URL" : "Message");
            row.tabIndex = 0;
            row.setAttribute(
                "aria-label",
                t("Open {type} scan details: {classification}", {
                    type: type.toLowerCase(),
                    classification: t(scan.prediction),
                })
            );
            row.addEventListener("click", () => showDashboardDetails(scan.id));
            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    showDashboardDetails(scan.id);
                }
            });

            const typeCell = document.createElement("td");
            typeCell.textContent = type;
            const contentCell = document.createElement("td");
            contentCell.className = "activity-preview";
            contentCell.textContent = scan.content || "";
            contentCell.title = scan.content || "";
            const resultCell = document.createElement("td");
            const badge = document.createElement("span");
            setBadge(badge, scan.prediction);
            resultCell.appendChild(badge);
            const scoreCell = document.createElement("td");
            scoreCell.textContent = String(scan.score) + "%";
            const dateCell = document.createElement("td");
            dateCell.textContent = formatTimestamp(scan.created_at);
            row.append(typeCell, contentCell, resultCell, scoreCell, dateCell);
            tableBody.appendChild(row);
        });
    }

    function renderDashboard(stats) {
        latestDashboardStats = stats;
        [
            ["total-messages", stats.messages],
            ["safe-count", stats.safe],
            ["spam-count", stats.spam],
            ["suspicious-count", stats.suspicious],
            ["urls-analysed", stats.urls],
            ["url-safe-count", stats.url_risk_counts.SAFE],
            ["url-suspicious-count", stats.url_risk_counts.SUSPICIOUS],
            ["url-spam-count", stats.url_risk_counts.SPAM],
            ["url-high-risk-count", stats.url_risk_counts["HIGH RISK"]],
        ].forEach(([elementId, value]) => {
            getElement(elementId).textContent = String(value);
        });
        renderChange("messages-change", stats.changes.messages, stats.range);
        renderChange("safe-change", stats.changes.safe, stats.range);
        renderChange("spam-change", stats.changes.spam, stats.range);
        renderChange("suspicious-change", stats.changes.suspicious, stats.range);
        renderChange("urls-change", stats.changes.urls, stats.range);
        renderScansPerDay(stats.scans_per_day);
        renderResults(stats);
        renderSources(stats.sources);
        renderCategories(stats.categories);
        renderKeywords(stats.top_keywords);
        renderRecentScans(stats.recent_scans);

        const isEmpty = stats.lifetime_total === 0;
        emptyState.hidden = !isEmpty;
        dashboardData.hidden = isEmpty;
        const updated = new Date();
        const updatedElement = getElement("last-updated");
        updatedElement.dateTime = updated.toISOString();
        updatedElement.textContent = new Intl.DateTimeFormat(
            getCurrentLanguage() === "hi" ? "hi-IN" : "en-IN", {
            dateStyle: "medium",
            timeStyle: "short",
            }
        ).format(updated);
    }

    async function loadDashboard() {
        if (activeController) {
            activeController.abort();
        }
        const controller = new AbortController();
        activeController = controller;
        dashboardPage.setAttribute("aria-busy", "true");
        errorElement.hidden = true;
        refreshButton.disabled = true;

        try {
            const query = new URLSearchParams({ range: rangeSelect.value });
            const response = await fetch(
                "/api/dashboard-stats?" + query.toString(),
                { signal: controller.signal }
            );
            const stats = await response.json();
            if (!response.ok) {
                throw new Error(stats.error || t("Dashboard data is unavailable."));
            }
            if (controller !== activeController) {
                return;
            }

            renderDashboard(stats);
            hasLoaded = true;
        } catch (error) {
            if (error.name !== "AbortError" && controller === activeController) {
                if (!hasLoaded) {
                    [
                        "total-messages",
                        "safe-count",
                        "spam-count",
                        "suspicious-count",
                        "urls-analysed",
                    ].forEach((elementId) => {
                        getElement(elementId).textContent = "—";
                    });
                    getElement("recent-scans-body").textContent =
                        t("Dashboard data is unavailable.");
                }
                showFriendlyError(
                    errorElement,
                    "Dashboard data could not be loaded. Please try again."
                );
            }
        } finally {
            if (controller === activeController) {
                dashboardPage.setAttribute("aria-busy", "false");
                refreshButton.disabled = false;
            }
        }
    }

    rangeSelect.addEventListener("change", loadDashboard);
    refreshButton.addEventListener("click", loadDashboard);
    window.addEventListener("spamshield:data-changed", loadDashboard);
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            loadDashboard();
        }
    });
    window.addEventListener("spamshield:languagechange", () => {
        if (latestDashboardStats) {
            renderDashboard(latestDashboardStats);
        }
        if (latestDetailsScan) {
            renderDashboardDetails(latestDetailsScan);
        }
    });
    if (dashboardUpdateChannel) {
        dashboardUpdateChannel.addEventListener("message", loadDashboard);
    }
    getElement("close-dashboard-details").addEventListener("click", () => {
        detailsDialog.close();
    });
    detailsDialog.addEventListener("click", (event) => {
        if (event.target === detailsDialog) {
            detailsDialog.close();
        }
    });
    window.setInterval(() => {
        if (document.visibilityState === "visible") {
            loadDashboard();
        }
    }, 30000);

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
        const localized = result.localizations
            ? result.localizations[getCurrentLanguage()]
            : result;
        return [
            t("SpamShield Message Estimate"),
            t("Classification") + ": " + t(result.classification),
            t("ML prediction") + ": " + t(result.ml_prediction),
            t("Spam probability") + ": " + result.confidence + "%",
            t("Risk level") + ": " + t(result.risk_level),
            t("Explanation") + ":",
            ...(localized.explanation || []).map((item) => "- " + item),
            t("Words to review") + ":",
            ...(result.suspicious_keywords || []).map((item) => "- " + item),
            t("Additional pattern checks") + ":",
            ...(localized.keyword_descriptions || []).map((item) => "- " + item),
            t("Suggested next step") + ": " + localized.recommended_action,
            t("Results are estimates. Independently verify suspicious messages."),
        ].join("\n");
    }

    function renderMessageResult(result) {
        const localized = result.localizations
            ? result.localizations[getCurrentLanguage()]
            : result;
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

        getElement("message-risk-level").textContent = t(result.risk_level || "");
        fillList(
            getElement("message-explanations"),
            localized.explanation,
            t("No explanation details were returned.")
        );
        fillList(
            getElement("message-keywords"),
            result.suspicious_keywords,
            t("No suspicious keywords were detected.")
        );

        const checkLabels = localized.keyword_descriptions || [];
        fillList(
            getElement("supplementary-checks-list"),
            checkLabels,
            t("No supplementary rule checks were triggered.")
        );
        getElement("recommended-action").textContent =
            localized.recommended_action || "";
        getElement("message-action-feedback").textContent = "";
        delete getElement("message-action-feedback").dataset.i18nLive;
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
                    lang: getCurrentLanguage(),
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
            notifyDashboardDataChanged();
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
                setRuntimeText(feedback, "Result copied.");
            } catch (error) {
                setRuntimeText(feedback, "Copy is unavailable in this browser.");
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
                    throw new Error(t("Report is unavailable."));
                }

                downloadTextFile(
                    "spamshield-message-report.json",
                    JSON.stringify(reportData.report, null, 2),
                    "application/json"
                );
                setRuntimeText(feedback, "Report downloaded.");
            } catch (error) {
                setRuntimeText(feedback, "Report could not be downloaded. Please try again.");
            } finally {
                downloadButton.disabled = false;
            }
        });
    }

    updateMessageCounter();
    window.addEventListener("spamshield:languagechange", () => {
        if (latestMessageResult) {
            renderMessageResult(latestMessageResult);
        }
    });
}

// URL scanner: send URL text only; this code never navigates to the submitted URL.
const urlForm = getElement("url-form");
if (urlForm) {
    const urlInput = getElement("url-text");
    const urlError = getElement("url-error");
    const urlResultCard = getElement("url-result");
    const urlSpinner = getElement("url-spinner");
    const checkUrlButton = getElement("check-url-button");
    let latestUrlResult = null;

    function renderUrlResult(result) {
        const localized = result.localizations
            ? result.localizations[getCurrentLanguage()]
            : result;
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
            localized.reasons,
            t("No suspicious URL patterns were detected.")
        );
        getElement("url-recommendation").textContent =
            localized.recommendation || "";
        getElement("url-note").textContent =
            (localized.note || t("This is a pattern-based check, not a threat-database lookup.")) +
            " " + t("The URL is not opened or visited.");
        urlResultCard.hidden = false;
    }

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
                body: JSON.stringify({ url: urlText, lang: getCurrentLanguage() }),
            });
            const result = await response.json();
            if (!response.ok) {
                showFriendlyError(
                    urlError,
                    result.error || "URL check failed. Please try again."
                );
                return;
            }

            latestUrlResult = result;
            renderUrlResult(result);
            notifyDashboardDataChanged();
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
    window.addEventListener("spamshield:languagechange", () => {
        if (latestUrlResult) {
            renderUrlResult(latestUrlResult);
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
    let latestHistory = [];
    let latestHistoryDetails = null;

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
                throw new Error(t("History could not be loaded."));
            }
            latestHistory = data.history || [];
            renderHistoryRows(latestHistory);
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
            typeCell.textContent = t(scan.scan_type || "");
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
            dateCell.textContent = scan.created_at
                ? formatHistoryTimestamp(scan.created_at)
                : "";
            row.appendChild(dateCell);

            const actionsCell = document.createElement("td");
            const actions = document.createElement("div");
            actions.className = "history-actions";
            const viewButton = document.createElement("button");
            viewButton.className = "small-action-button";
            viewButton.type = "button";
            viewButton.textContent = t("View");
            viewButton.addEventListener("click", () => showScanDetails(scanId));

            const deleteButton = document.createElement("button");
            deleteButton.className = "small-action-button delete-scan";
            deleteButton.type = "button";
            deleteButton.textContent = t("Delete");
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

    function formatHistoryTimestamp(value) {
        const date = new Date(String(value).replace(" ", "T") + "Z");
        return Number.isNaN(date.getTime())
            ? String(value)
            : new Intl.DateTimeFormat(
                getCurrentLanguage() === "hi" ? "hi-IN" : "en-IN",
                { dateStyle: "medium", timeStyle: "short" }
            ).format(date);
    }

    async function showScanDetails(scanId) {
        historyError.hidden = true;
        try {
            const response = await fetch(
                "/api/history/" + encodeURIComponent(String(scanId))
            );
            const scan = await response.json();
            if (!response.ok) {
                throw new Error(t("Scan details could not be loaded."));
            }

            latestHistoryDetails = scan;
            renderHistoryDetails(scan);
            detailsDialog.showModal();
        } catch (error) {
            showFriendlyError(
                historyError,
                "Scan details are unavailable right now. Please try again."
            );
        }
    }

    function renderHistoryDetails(scan) {
            const detailsElement = getElement("history-details-content");
            detailsElement.replaceChildren();
            appendDetail(detailsElement, t("Type"), t(scan.scan_type || ""));
            appendDetail(detailsElement, t("Source"), t(scan.source || ""));
            appendDetail(detailsElement, t("Classification"), t(scan.prediction || ""));
            appendDetail(detailsElement, t("Score"), String(scan.score) + "%");
            appendDetail(
                detailsElement,
                t("Date and time"),
                formatHistoryTimestamp(scan.created_at)
            );
            appendDetail(detailsElement, t("Content"), scan.content);
            appendDetail(detailsElement, t("Explanation"), scan.explanation);
            appendDetail(detailsElement, t("Flags"), scan.flags);
    }

    async function deleteOneScan(scanId) {
        if (!window.confirm(t("Delete this scan from history?"))) {
            return;
        }

        try {
            const response = await fetch(
                "/api/history/" + encodeURIComponent(String(scanId)),
                { method: "DELETE" }
            );
            if (!response.ok) {
                throw new Error(t("Scan could not be deleted."));
            }
            await loadHistory();
            notifyDashboardDataChanged();
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
        if (!window.confirm(t("Clear all scan history? This cannot be undone."))) {
            return;
        }

        historyError.hidden = true;
        try {
            const response = await fetch("/api/history", { method: "DELETE" });
            if (!response.ok) {
                throw new Error(t("History could not be cleared."));
            }
            await loadHistory();
            notifyDashboardDataChanged();
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
    window.addEventListener("spamshield:languagechange", () => {
        renderHistoryRows(latestHistory);
        if (latestHistoryDetails) {
            renderHistoryDetails(latestHistoryDetails);
        }
    });
}

function initializePasswordToggles(form) {
    form.querySelectorAll("[data-password-toggle]").forEach((button) => {
        const input = getElement(button.getAttribute("data-password-toggle"));
        function updateToggleLabel() {
            const isVisible = input.type === "text";
            button.textContent = t(isVisible ? "Hide" : "Show");
            button.setAttribute(
                "aria-label",
                t(isVisible ? "Hide password" : "Show password")
            );
        }
        button.addEventListener("click", () => {
            const showPassword = input.type === "password";
            input.type = showPassword ? "text" : "password";
            button.setAttribute("aria-pressed", String(showPassword));
            updateToggleLabel();
        });
        window.addEventListener("spamshield:languagechange", updateToggleLabel);
    });
}

const registerForm = getElement("register-form");
if (registerForm) {
    const nameInput = getElement("register-name");
    const emailInput = getElement("register-email");
    const passwordInput = getElement("register-password");
    const confirmInput = getElement("register-confirm-password");
    const strengthLabel = getElement("password-strength");
    const strengthMeter = getElement("password-strength-meter");
    const submitButton = getElement("register-submit");
    const spinner = getElement("register-spinner");
    const formError = getElement("auth-error");
    const rules = {
        length: (password) => password.length >= 8,
        uppercase: (password) => Array.from(password).some(
            (character) => character.toUpperCase() === character
                && character.toLowerCase() !== character
        ),
        lowercase: (password) => Array.from(password).some(
            (character) => character.toLowerCase() === character
                && character.toUpperCase() !== character
        ),
        number: (password) => /[0-9]/.test(password),
        special: (password) => Array.from(password).some(
            (character) => !/[\p{L}\p{N}\s]/u.test(character)
        ),
    };

    initializePasswordToggles(registerForm);

    function updatePasswordStrength() {
        const password = passwordInput.value;
        const emailName = emailInput.value.split("@", 1)[0].toLowerCase();
        const requirementsMet = Object.values(rules).every((rule) => rule(password));
        const isCommon = ["password", "12345678", "qwerty123"]
            .includes(password.toLowerCase());
        const containsEmailName = emailName && password.toLowerCase()
            .includes(emailName);

        // Password strength is rule-based and follows the server's validation.
        let strength = "Weak";
        if (requirementsMet && !isCommon && !containsEmailName) {
            if (password.length >= 16) {
                strength = "Strong";
            } else if (password.length >= 12) {
                strength = "Good";
            } else {
                strength = "Fair";
            }
        }

        Object.entries(rules).forEach(([ruleName, rule]) => {
            const item = registerForm.querySelector(
                '[data-password-rule="' + ruleName + '"]'
            );
            const met = rule(password);
            item.classList.toggle("is-met", met);
            item.querySelector("i").className = met
                ? "fa-solid fa-circle-check"
                : "fa-regular fa-circle";
        });

        strengthLabel.textContent = t(strength);
        strengthMeter.dataset.strength = strength;
        strengthMeter.setAttribute(
            "aria-valuenow",
            String({ Weak: 1, Fair: 2, Good: 3, Strong: 4 }[strength])
        );
        submitButton.disabled =
            strength === "Weak"
            || !confirmInput.value
            || password !== confirmInput.value;

        const confirmError = getElement("confirm-password-error");
        if (confirmInput.value && password !== confirmInput.value) {
            setRuntimeText(confirmError, "Passwords do not match.");
            confirmError.hidden = false;
        } else {
            confirmError.hidden = true;
        }
        return strength;
    }

    passwordInput.addEventListener("input", updatePasswordStrength);
    emailInput.addEventListener("input", updatePasswordStrength);
    confirmInput.addEventListener("input", updatePasswordStrength);
    updatePasswordStrength();
    window.addEventListener("spamshield:languagechange", updatePasswordStrength);

    registerForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        formError.hidden = true;
        const nameError = getElement("register-name-error");
        const emailError = getElement("register-email-error");
        const passwordError = getElement("register-password-error");
        [nameError, emailError, passwordError].forEach((error) => {
            error.textContent = "";
            delete error.dataset.i18nLive;
            error.hidden = true;
        });

        if (nameInput.value.trim().length < 2 || nameInput.value.trim().length > 50) {
            setRuntimeText(nameError, "Enter a name between 2 and 50 characters.");
            nameError.hidden = false;
            nameInput.focus();
            return;
        }
        const emailPattern = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
        if (emailInput.value.length > 254 || !emailPattern.test(emailInput.value)) {
            setRuntimeText(emailError, "Enter a valid email address.");
            emailError.hidden = false;
            emailInput.focus();
            return;
        }
        if (!passwordInput.value) {
            setRuntimeText(passwordError, "Enter a password.");
            passwordError.hidden = false;
            passwordInput.focus();
            return;
        }
        if (!confirmInput.value) {
            const confirmError = getElement("confirm-password-error");
            setRuntimeText(confirmError, "Confirm your password.");
            confirmError.hidden = false;
            confirmInput.focus();
            return;
        }
        if (!registerForm.reportValidity()) {
            return;
        }
        if (updatePasswordStrength() === "Weak") {
            setRuntimeText(passwordError, "Choose a password that meets all the listed rules.");
            passwordError.hidden = false;
            passwordInput.focus();
            return;
        }
        if (passwordInput.value !== confirmInput.value) {
            const confirmError = getElement("confirm-password-error");
            setRuntimeText(confirmError, "Passwords do not match.");
            confirmError.hidden = false;
            confirmInput.focus();
            return;
        }

        submitButton.disabled = true;
        spinner.hidden = false;
        submitButton.querySelector(".button-label").hidden = true;
        try {
            const response = await fetch(registerForm.action, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(Object.fromEntries(new FormData(registerForm))),
            });
            const result = await response.json();
            if (result.password_strength) {
                strengthLabel.textContent = t(result.password_strength);
                strengthMeter.dataset.strength = result.password_strength;
            }
            if (!response.ok) {
                const message = result.error || "We could not create your account.";
                if (message.includes("Name must")) {
                    setRuntimeText(nameError, message);
                    nameError.hidden = false;
                } else if (message.includes("valid email") || message.includes("already exists")) {
                    setRuntimeText(emailError, message);
                    emailError.hidden = false;
                } else if (message.includes("Password must")) {
                    setRuntimeText(passwordError, message);
                    passwordError.hidden = false;
                } else if (message.includes("Passwords do not match")) {
                    const confirmError = getElement("confirm-password-error");
                    setRuntimeText(confirmError, message);
                    confirmError.hidden = false;
                } else {
                    showFriendlyError(formError, message);
                }
                return;
            }
            window.location.assign("/login");
        } catch (error) {
            showFriendlyError(formError, "We could not create your account. Please try again.");
        } finally {
            spinner.hidden = true;
            submitButton.querySelector(".button-label").hidden = false;
            updatePasswordStrength();
        }
    });
}

const loginForm = getElement("login-form");
if (loginForm) {
    const emailInput = getElement("login-email");
    const passwordInput = getElement("login-password");
    const submitButton = getElement("login-submit");
    const spinner = getElement("login-spinner");
    const errorElement = getElement("auth-error");
    const lockMessage = getElement("login-lock-message");

    initializePasswordToggles(loginForm);
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        errorElement.hidden = true;
        lockMessage.hidden = true;
        if (!loginForm.reportValidity()) {
            return;
        }

        submitButton.disabled = true;
        spinner.hidden = false;
        submitButton.querySelector(".button-label").hidden = true;
        try {
            const response = await fetch(loginForm.action, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(Object.fromEntries(new FormData(loginForm))),
            });
            const result = await response.json();
            if (!response.ok) {
                showFriendlyError(
                    errorElement,
                    result.error || "Incorrect email or password"
                );
                if (result.account_locked) {
                    setRuntimeText(
                        lockMessage,
                        result.lock_message
                            || "Too many failed attempts. Try again in five minutes."
                    );
                    lockMessage.hidden = false;
                }
                return;
            }
            window.location.assign("/dashboard");
        } catch (error) {
            showFriendlyError(errorElement, "Unable to log in right now. Please try again.");
        } finally {
            submitButton.disabled = false;
            spinner.hidden = true;
            submitButton.querySelector(".button-label").hidden = false;
        }
    });
}
