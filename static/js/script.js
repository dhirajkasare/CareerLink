document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const submitButton = form.querySelector(".auth-submit-button");
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = "Please wait...";
            }
        });
    });

    const resendOtpButton = document.getElementById("resendOtpButton");
    if (resendOtpButton) {
        let remainingSeconds = Number(resendOtpButton.dataset.cooldown || 45);
        const originalLabel = resendOtpButton.textContent;
        resendOtpButton.disabled = true;

        const cooldownTimer = window.setInterval(() => {
            if (remainingSeconds <= 0) {
                window.clearInterval(cooldownTimer);
                resendOtpButton.disabled = false;
                resendOtpButton.textContent = originalLabel;
                return;
            }

            resendOtpButton.textContent = `Resend OTP in ${remainingSeconds}s`;
            remainingSeconds -= 1;
        }, 1000);
    }

    const confirmationTriggers = document.querySelectorAll("[data-confirm-title]");
    const deleteForms = document.querySelectorAll("form[action*='delete']");
    const actionModalElement = document.getElementById("adminActionModal");
    const deleteModalElement = document.getElementById("deleteActionModal");
    const actionModalTitle = document.getElementById("adminActionModalTitle");
    const actionModalMessage = document.getElementById("adminActionModalMessage");
    const actionModalConfirm = document.getElementById("adminActionModalConfirm");
    const deleteConfirmInput = document.getElementById("deleteConfirmInput");
    const deleteModalConfirm = document.getElementById("deleteActionModalConfirm");
    const actionModal = actionModalElement ? new bootstrap.Modal(actionModalElement) : null;
    const deleteModal = deleteModalElement ? new bootstrap.Modal(deleteModalElement) : null;
    let pendingCallback = null;

    if (confirmationTriggers.length && actionModal && actionModalTitle && actionModalMessage && actionModalConfirm) {
        confirmationTriggers.forEach((trigger) => {
            trigger.addEventListener("click", (event) => {
                const title = trigger.dataset.confirmTitle;
                const message = trigger.dataset.confirmMessage;
                const actionLabel = trigger.dataset.confirmAction || "Continue";

                event.preventDefault();
                actionModalTitle.textContent = title;
                actionModalMessage.textContent = message;
                actionModalConfirm.textContent = actionLabel;
                pendingCallback = () => {
                    if (trigger.tagName === "A") {
                        window.location.href = trigger.href;
                        return;
                    }

                    const parentForm = trigger.closest("form");
                    if (parentForm) {
                        parentForm.submit();
                    }
                };
                actionModal.show();
            });
        });

        actionModalConfirm.addEventListener("click", () => {
            if (pendingCallback) {
                pendingCallback();
            }
        });

        actionModalElement.addEventListener("hidden.bs.modal", () => {
            pendingCallback = null;
        });
    }

    if (deleteForms.length && deleteModal && deleteConfirmInput && deleteModalConfirm) {
        deleteForms.forEach((form) => {
            form.addEventListener("submit", (event) => {
                event.preventDefault();
                pendingCallback = () => form.submit();
                deleteConfirmInput.value = "";
                deleteModalConfirm.disabled = true;
                deleteModal.show();
            });
        });

        deleteConfirmInput.addEventListener("input", () => {
            deleteModalConfirm.disabled = deleteConfirmInput.value.trim().toUpperCase() !== "DELETE";
        });

        deleteModalConfirm.addEventListener("click", () => {
            if (pendingCallback) {
                pendingCallback();
            }
        });

        deleteModalElement.addEventListener("hidden.bs.modal", () => {
            pendingCallback = null;
            deleteConfirmInput.value = "";
            deleteModalConfirm.disabled = true;
        });
    }

    const selectAllJobsButton = document.getElementById("selectAllJobsButton");
    const selectAllJobsCheckbox = document.getElementById("selectAllJobsCheckbox");
    const jobSelectCheckboxes = Array.from(document.querySelectorAll(".job-select-checkbox"));
    const selectedJobsCount = document.getElementById("selectedJobsCount");
    const deleteSelectedJobsButton = document.getElementById("deleteSelectedJobsButton");
    let allJobsSelected = false;

    const updateSelectedJobsState = () => {
        if (!jobSelectCheckboxes.length) {
            return;
        }

        const checkedCount = jobSelectCheckboxes.filter((checkbox) => checkbox.checked).length;
        const hasSelection = checkedCount > 0;
        const allSelected = checkedCount === jobSelectCheckboxes.length;

        if (selectedJobsCount) {
            selectedJobsCount.textContent = `${checkedCount} selected`;
        }
        if (deleteSelectedJobsButton) {
            deleteSelectedJobsButton.disabled = !hasSelection;
        }
        if (selectAllJobsCheckbox) {
            selectAllJobsCheckbox.checked = allSelected;
            selectAllJobsCheckbox.indeterminate = hasSelection && !allSelected;
        }
        if (selectAllJobsButton) {
            selectAllJobsButton.textContent = allSelected ? "Clear Selection" : "Select All";
        }

        allJobsSelected = allSelected;
    };

    if (jobSelectCheckboxes.length) {
        jobSelectCheckboxes.forEach((checkbox) => {
            checkbox.addEventListener("change", updateSelectedJobsState);
        });

        selectAllJobsCheckbox?.addEventListener("change", () => {
            jobSelectCheckboxes.forEach((checkbox) => {
                checkbox.checked = selectAllJobsCheckbox.checked;
            });
            updateSelectedJobsState();
        });

        selectAllJobsButton?.addEventListener("click", () => {
            const shouldSelectAll = !allJobsSelected;
            jobSelectCheckboxes.forEach((checkbox) => {
                checkbox.checked = shouldSelectAll;
            });
            updateSelectedJobsState();
        });

        updateSelectedJobsState();
    }

    const supportChatToggle = document.getElementById("supportChatToggle");
    const supportChatPanel = document.getElementById("supportChatPanel");
    const supportChatClose = document.getElementById("supportChatClose");
    const supportChatForm = document.getElementById("supportChatForm");
    const supportChatInput = document.getElementById("supportChatInput");
    const supportChatMessages = document.getElementById("supportChatMessages");

    const appendSupportMessage = (text, type) => {
        if (!supportChatMessages) {
            return;
        }

        const message = document.createElement("div");
        message.className = `support-chat__message support-chat__message--${type}`;
        message.textContent = text;
        supportChatMessages.appendChild(message);
        supportChatMessages.scrollTop = supportChatMessages.scrollHeight;
    };

    if (supportChatToggle && supportChatPanel) {
        supportChatToggle.addEventListener("click", () => {
            const isHidden = supportChatPanel.hasAttribute("hidden");
            if (isHidden) {
                supportChatPanel.removeAttribute("hidden");
                supportChatInput?.focus();
            } else {
                supportChatPanel.setAttribute("hidden", "");
            }
        });
    }

    if (supportChatClose && supportChatPanel) {
        supportChatClose.addEventListener("click", () => {
            supportChatPanel.setAttribute("hidden", "");
        });
    }

    if (supportChatForm) {
        supportChatForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const message = supportChatInput?.value.trim();
            if (!message) {
                return;
            }

            appendSupportMessage(message, "user");
            supportChatInput.value = "";

            try {
                const response = await fetch("/support-chat", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ message }),
                });
                const data = await response.json();
                appendSupportMessage(data.reply || "I could not find an answer right now.", "bot");
            } catch (error) {
                appendSupportMessage("Support is temporarily unavailable. Please try again in a moment.", "bot");
            }
        });
    }

    const fraudForm = document.getElementById("fraudAnalysisForm");
    const fraudLoading = document.getElementById("fraudLoading");
    const fraudAlert = document.getElementById("fraudAlert");
    const fraudEmptyState = document.getElementById("fraudEmptyState");
    const fraudResults = document.getElementById("fraudResults");
    const jobDescriptionInput = document.getElementById("jobDescription");
    const analyzeButton = document.getElementById("fraudAnalyzeButton");

    const setFraudCheck = (elementId, label, value, truthyText = "Yes", falsyText = "No", positiveWhenTruthy = true) => {
        const element = document.getElementById(elementId);
        if (!element) {
            return;
        }

        const matchesTruthy = Boolean(value);
        const isPositive = positiveWhenTruthy ? matchesTruthy : !matchesTruthy;
        element.innerHTML = `
            <span class="fraud-check-item__icon ${isPositive ? "fraud-check-item__icon--good" : "fraud-check-item__icon--warn"}">
                ${isPositive ? "OK" : "!"}
            </span>
            <span class="fraud-check-item__text">
                <strong>${label}</strong>
                <small>${matchesTruthy ? truthyText : falsyText}</small>
            </span>
        `;
    };

    const showFraudError = (message) => {
        if (fraudAlert) {
            fraudAlert.hidden = false;
            fraudAlert.textContent = message;
        }
    };

    const hideFraudError = () => {
        if (fraudAlert) {
            fraudAlert.hidden = true;
            fraudAlert.textContent = "";
        }
    };

    const renderFraudAnalysis = (analysis) => {
        const classification = analysis.classification || "FAKE";
        const classificationTitle = document.getElementById("classificationTitle");
        const classificationSubtitle = document.getElementById("classificationSubtitle");
        const classificationBadge = document.getElementById("classificationBadge");
        const riskScoreValue = document.getElementById("riskScoreValue");
        const confidenceValue = document.getElementById("confidenceValue");
        const riskScoreBar = document.getElementById("riskScoreBar");
        const confidenceBar = document.getElementById("confidenceBar");
        const recommendationBadge = document.getElementById("recommendationBadge");
        const recommendationText = document.getElementById("recommendationText");
        const scamIndicatorsList = document.getElementById("scamIndicatorsList");
        const fraudExplanation = document.getElementById("fraudExplanation");

        if (!classificationBadge || !riskScoreValue || !confidenceValue || !riskScoreBar || !confidenceBar || !recommendationBadge || !recommendationText || !scamIndicatorsList || !fraudExplanation) {
            return;
        }

        const riskScore = Number(analysis.risk_score || 0);
        const confidence = Number(analysis.confidence || 0);
        const recommendation = String(analysis.recommended_action || "caution").toUpperCase();
        const classificationClass = classification === "LEGITIMATE" ? "fraud-status-badge--safe" : "fraud-status-badge--danger";
        const recommendationClass = recommendation === "SAFE"
            ? "fraud-recommendation--safe"
            : recommendation === "AVOID"
                ? "fraud-recommendation--avoid"
                : "fraud-recommendation--caution";

        classificationBadge.className = `fraud-status-badge ${classificationClass}`;
        classificationBadge.textContent = classification;
        classificationTitle.textContent = classification === "LEGITIMATE" ? "This posting appears more trustworthy." : "This posting shows warning signs.";
        classificationSubtitle.textContent = classification === "LEGITIMATE"
            ? "The job ad does not show major scam signals, but you should still verify the employer before applying."
            : "The job ad contains red flags that suggest you should be careful before sharing personal or financial information.";

        riskScoreValue.textContent = `${riskScore}%`;
        confidenceValue.textContent = `${confidence}%`;
        riskScoreBar.style.width = `${riskScore}%`;
        confidenceBar.style.width = `${confidence}%`;

        recommendationBadge.className = `fraud-recommendation ${recommendationClass}`;
        recommendationBadge.textContent = recommendation;
        recommendationText.textContent = analysis.explanation || "No explanation returned.";
        fraudExplanation.textContent = analysis.explanation || "No explanation returned.";

        scamIndicatorsList.innerHTML = "";
        const indicators = Array.isArray(analysis.scam_indicators) ? analysis.scam_indicators : [];
        if (!indicators.length) {
            scamIndicatorsList.innerHTML = `
                <li class="fraud-indicator-list__item fraud-indicator-list__item--clear">
                    <span class="fraud-indicator-list__icon">OK</span>
                    <span>No major scam indicators were detected in the posting.</span>
                </li>
            `;
        } else {
            indicators.forEach((indicator) => {
                const item = document.createElement("li");
                item.className = "fraud-indicator-list__item";
                item.innerHTML = `
                    <span class="fraud-indicator-list__icon">!</span>
                    <span>${indicator}</span>
                `;
                scamIndicatorsList.appendChild(item);
            });
        }

        setFraudCheck("companyPresentCheck", "Company mentioned", analysis.company_analysis?.company_present, "Company name is present", "No company name was found");
        setFraudCheck("companyVerifiableCheck", "Company verifiable", analysis.company_analysis?.company_verifiable, "Details appear verifiable", "The employer looks difficult to verify");
        setFraudCheck("freeEmailCheck", "Free email used", analysis.contact_analysis?.uses_free_email, "A free email domain is used", "No free email domain detected", false);
        setFraudCheck("messagingCheck", "Messaging apps used", analysis.contact_analysis?.uses_messaging_apps, "WhatsApp or Telegram style contact detected", "No messaging-app contact detected", false);
        setFraudCheck("salaryPresentCheck", "Salary included", analysis.salary_analysis?.salary_present, "Salary information is present", "No salary information was found");
        setFraudCheck("salaryUnrealisticCheck", "Salary realism", analysis.salary_analysis?.salary_unrealistic, "Compensation looks unrealistic", "No obvious salary exaggeration detected", false);

        const grammarQualityCheck = document.getElementById("grammarQualityCheck");
        if (grammarQualityCheck) {
            grammarQualityCheck.innerHTML = `
                <span class="fraud-check-item__icon fraud-check-item__icon--neutral">A</span>
                <span class="fraud-check-item__text">
                    <strong>Grammar quality</strong>
                    <small>${analysis.text_quality?.grammar_quality || "moderate"}</small>
                </span>
            `;
        }

        setFraudCheck("genericDescriptionCheck", "Generic description", analysis.text_quality?.generic_description, "The job description feels generic", "The posting has role-specific detail", false);
    };

    if (fraudForm && jobDescriptionInput && fraudResults && fraudEmptyState) {
        fraudForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const jobText = jobDescriptionInput.value.trim();

            hideFraudError();
            if (!jobText) {
                showFraudError("Please paste a job posting before starting the analysis.");
                return;
            }

            fraudLoading?.removeAttribute("hidden");
            analyzeButton?.setAttribute("disabled", "disabled");

            try {
                const response = await fetch("/analyze-job", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ job_text: jobText }),
                });
                const data = await response.json();

                if (!response.ok || !data.success) {
                    throw new Error(data.error || "We could not complete the analysis right now.");
                }

                renderFraudAnalysis(data.analysis || {});
                fraudEmptyState.hidden = true;
                fraudResults.hidden = false;
            } catch (error) {
                fraudResults.hidden = true;
                fraudEmptyState.hidden = false;
                showFraudError(error.message || "We could not complete the analysis right now.");
            } finally {
                fraudLoading?.setAttribute("hidden", "");
                analyzeButton?.removeAttribute("disabled");
            }
        });
    }

    const resumeForm = document.getElementById("resumeAnalysisForm");
    const resumeInput = document.getElementById("resume");
    const resumeLoading = document.getElementById("resumeLoading");
    const resumeAlert = document.getElementById("resumeAlert");
    const resumeEmptyState = document.getElementById("resumeEmptyState");
    const resumeResults = document.getElementById("resumeResults");
    const resumeAnalyzeButton = document.getElementById("resumeAnalyzeButton");
    const resumeStatusChip = document.getElementById("resumeStatusChip");

    const setResumeStatus = (label, state = "") => {
        if (!resumeStatusChip) {
            return;
        }

        resumeStatusChip.className = "resume-status-chip";
        if (state) {
            resumeStatusChip.classList.add(`resume-status-chip--${state}`);
        }
        resumeStatusChip.textContent = label;
    };

    const showResumeError = (message, label = "Needs Attention") => {
        if (resumeAlert) {
            resumeAlert.hidden = false;
            resumeAlert.textContent = message;
        }
        setResumeStatus(label, "error");
    };

    const hideResumeError = () => {
        if (resumeAlert) {
            resumeAlert.hidden = true;
            resumeAlert.textContent = "";
        }
    };

    const renderResumeList = (elementId, items, variant = "default") => {
        const element = document.getElementById(elementId);
        if (!element) {
            return;
        }

        element.innerHTML = "";
        const safeItems = Array.isArray(items) && items.length ? items : ["No items returned."];
        safeItems.forEach((item, index) => {
            const entry = document.createElement("li");
            entry.className = `resume-list__item${variant === "warning" ? " resume-list__item--warning" : ""}`;
            entry.innerHTML = `
                <span class="resume-list__marker">${index + 1}</span>
                <span>${item}</span>
            `;
            element.appendChild(entry);
        });
    };

    const renderResumeBadges = (elementId, items, emptyLabel) => {
        const element = document.getElementById(elementId);
        if (!element) {
            return;
        }

        element.innerHTML = "";
        const safeItems = Array.isArray(items) && items.length ? items : [emptyLabel];
        safeItems.forEach((item, index) => {
            const badge = document.createElement("span");
            badge.className = `resume-badge${!Array.isArray(items) || !items.length ? " resume-badge--neutral" : ""}`;
            badge.textContent = item;
            badge.dataset.index = String(index);
            element.appendChild(badge);
        });
    };

    const renderResumeAnalysis = (analysis) => {
        const resumeScoreValue = document.getElementById("resumeScoreValue");
        const resumeScoreBar = document.getElementById("resumeScoreBar");
        const resumeSummaryText = document.getElementById("resumeSummaryText");
        const resumeScoreRing = document.querySelector(".resume-score-hero__ring");
        const score = Number(analysis.resume_score || 0);
        const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
        const scoreDegrees = Math.round((clampedScore / 100) * 360);

        if (resumeScoreValue) {
            resumeScoreValue.textContent = String(clampedScore);
        }
        if (resumeScoreBar) {
            resumeScoreBar.style.width = `${clampedScore}%`;
        }
        if (resumeScoreRing) {
            resumeScoreRing.style.background = `radial-gradient(circle closest-side, #fff 74%, transparent 75% 100%), conic-gradient(#2fba7d 0deg, #2fba7d ${scoreDegrees}deg, #dff1e7 ${scoreDegrees}deg 360deg)`;
        }
        if (resumeSummaryText) {
            resumeSummaryText.textContent = analysis.summary || "No summary was returned.";
        }

        renderResumeList("resumeStrengthsList", analysis.strengths || []);
        renderResumeList("resumeWeaknessesList", analysis.weaknesses || [], "warning");
        renderResumeList("resumeTipsList", analysis.improvement_tips || []);
        renderResumeBadges("resumeMissingSectionsList", analysis.missing_sections || [], "No major missing sections detected");
        renderResumeBadges("resumeSuggestedSkillsList", analysis.suggested_skills || [], "No additional skills suggested");
    };

    if (resumeForm && resumeInput && resumeResults && resumeEmptyState) {
        resumeForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            hideResumeError();

            const file = resumeInput.files?.[0];
            if (!file) {
                showResumeError("Please choose a PDF resume before starting the analysis.");
                return;
            }

            if (!file.name.toLowerCase().endsWith(".pdf")) {
                showResumeError("Only PDF resumes are supported for analysis.");
                return;
            }

            const formData = new FormData();
            formData.append("resume", file);

            resumeLoading?.removeAttribute("hidden");
            resumeAnalyzeButton?.setAttribute("disabled", "disabled");
            setResumeStatus("Analyzing", "loading");

            try {
                const response = await fetch("/analyze-resume", {
                    method: "POST",
                    body: formData,
                });
                const data = await response.json();
                const analysis = data.analysis || {};

                if (!response.ok && !analysis.summary) {
                    throw new Error(data.error || "We could not complete the resume analysis right now.");
                }

                renderResumeAnalysis(analysis);
                resumeEmptyState.hidden = true;
                resumeResults.hidden = false;

                if (data.success) {
                    setResumeStatus("Analysis Ready", "success");
                } else if (data.error) {
                    showResumeError(data.error, "Partial Result");
                }
            } catch (error) {
                resumeResults.hidden = true;
                resumeEmptyState.hidden = false;
                showResumeError(error.message || "We could not complete the resume analysis right now.");
            } finally {
                resumeLoading?.setAttribute("hidden", "");
                resumeAnalyzeButton?.removeAttribute("disabled");
            }
        });
    }

    const dashboardData = window.dashboardData;
    if (dashboardData) {
        const baseOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#5f6b94",
                        font: {
                            family: "Outfit",
                            weight: "600",
                        },
                    },
                },
            },
            scales: {
                x: {
                    ticks: {
                        color: "#5f6b94",
                        font: { family: "Outfit" },
                    },
                    grid: { color: "#edf1fb" },
                    border: { color: "#edf1fb" },
                },
                y: {
                    ticks: {
                        color: "#5f6b94",
                        font: { family: "Outfit" },
                    },
                    grid: { color: "#edf1fb" },
                    border: { color: "#edf1fb" },
                },
            },
        };

        const palette = ["#5b46f6", "#6c7cff", "#4c98ff", "#2fba7d", "#ffb340", "#ff7b91", "#8d95c9", "#6fd7ff"];

        const skillsChartEl = document.getElementById("skillsChart");
        if (skillsChartEl) {
            new Chart(skillsChartEl, {
                type: "bar",
                data: {
                    labels: dashboardData.skills_labels,
                    datasets: [{
                        label: "Demand Count",
                        data: dashboardData.skills_values,
                        backgroundColor: palette.slice(0, dashboardData.skills_values.length),
                        borderRadius: 14,
                        borderSkipped: false,
                    }],
                },
                options: baseOptions,
            });
        }

        const locationsChartEl = document.getElementById("locationsChart");
        if (locationsChartEl) {
            new Chart(locationsChartEl, {
                type: "doughnut",
                data: {
                    labels: dashboardData.location_labels,
                    datasets: [{
                        data: dashboardData.location_values,
                        backgroundColor: palette.slice(0, dashboardData.location_values.length),
                        borderWidth: 4,
                        borderColor: "#ffffff",
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                color: "#5f6b94",
                                font: {
                                    family: "Outfit",
                                    weight: "600",
                                },
                            },
                        },
                    },
                },
            });
        }

        const companiesChartEl = document.getElementById("companiesChart");
        if (companiesChartEl) {
            new Chart(companiesChartEl, {
                type: "bar",
                data: {
                    labels: dashboardData.company_labels,
                    datasets: [{
                        label: "Openings",
                        data: dashboardData.company_values,
                        backgroundColor: palette.slice(0, dashboardData.company_values.length),
                        borderRadius: 14,
                        borderSkipped: false,
                    }],
                },
                options: baseOptions,
            });
        }
    }
});
