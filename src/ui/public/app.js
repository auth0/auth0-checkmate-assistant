const ui = { state: null, cards: new Map() };

const byId = (id) => document.getElementById(id);
const node = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};

function findingScope() {
  const validators = ui.state.reportValidatorCount;
  const details = ui.state.reportFindingCount;
  return `${validators} reported validator${validators === 1 ? "" : "s"} with ${details} detail item${details === 1 ? "" : "s"}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.error || "The request failed.");
    error.responseBody = body;
    throw error;
  }
  return body;
}

let toastTimer;
let toastDismissBound = false;
function hideToast() {
  const target = byId("toast");
  if (target) target.className = "toast";
}
function toast(message, error = false) {
  const target = byId("toast");
  target.textContent = message;
  // Error toasts persist until dismissed so they can be read and acted on;
  // success toasts auto-hide after a few seconds.
  target.className = `toast show${error ? " error dismissible" : ""}`;
  clearTimeout(toastTimer);
  if (!toastDismissBound) {
    target.addEventListener("click", hideToast);
    toastDismissBound = true;
  }
  if (!error) {
    toastTimer = setTimeout(hideToast, 3500);
  }
}

function renderProgress() {
  const { completed, total } = ui.state.progress;
  byId("progress-label").textContent = ui.state.scanning
    ? "CheckMate scan in progress"
    : !ui.state.hasReport
      ? "Ready to scan"
      : ui.state.triaged
        ? `${completed} of ${total} reviewed`
        : `Preparing recommendations for ${findingScope()}`;
  byId("progress-bar").style.width =
    `${total ? (completed / total) * 100 : 0}%`;
}

function renderScanLoading(profile) {
  ui.state.scanning = true;
  renderProgress();
  byId("workspace").classList.remove("review-workspace");
  const page = node("section", "triage-page");
  page.append(
    node("div", "spinner", ""),
    node("h1", "", "CheckMate is scanning the tenant"),
    node(
      "p",
      "",
      `Running the read-only assessment against the ${profile} profile. This can take a few minutes.`,
    ),
  );
  byId("workspace").replaceChildren(page);
}

function renderStartPage() {
  renderProgress();
  byId("workspace").classList.remove("review-workspace");
  const page = node("section", "scan-start-page");
  const content = node("div", "scan-start-content");
  content.append(
    node("div", "eyebrow", "Start a new assessment"),
    node("h1", "", "Run CheckMate"),
    node(
      "p",
      "scan-intro",
      "CheckMate reads the Auth0 tenant configuration and creates a JSON security report. Deterministic remediation guidance starts after the report is ready.",
    ),
  );
  const prerequisite = node("section", "scan-prerequisite");
  prerequisite.append(
    node("div", "scan-prerequisite-label", "Assessment prerequisite"),
    node("h2", "", "Development must mirror production configuration"),
    node(
      "p",
      "",
      "Before starting, the development tenant must have exactly the same security-relevant Auth0 configuration as the production tenant. This makes the assessment and proposed changes representative of production.",
    ),
    node(
      "p",
      "scan-prerequisite-detail",
      "Keep environment-specific tenant domains, resource IDs, credentials, users, logs, and customer data separate.",
    ),
  );
  const confirmationLabel = node("label", "scan-prerequisite-confirmation");
  const confirmation = document.createElement("input");
  confirmation.type = "checkbox";
  confirmationLabel.append(
    confirmation,
    node(
      "span",
      "",
      "I confirm the development tenant mirrors the production configuration baseline.",
    ),
  );
  prerequisite.append(confirmationLabel);
  content.append(prerequisite);
  const form = node("div", "scan-form");
  const label = node("label", "scan-profile-label", "Tenant profile");
  const select = document.createElement("select");
  select.className = "scan-profile";
  select.setAttribute("aria-label", "Tenant profile");
  const available = ui.state.availableProfiles || [];
  for (const profile of available) {
    const option = document.createElement("option");
    option.value = profile;
    option.textContent =
      profile === "dev" ? "Development" : "Production (scan only)";
    option.selected =
      profile ===
      (ui.state.selectedProfile ||
        (available.includes("dev") ? "dev" : available[0]));
    select.append(option);
  }
  label.append(select);
  const run = node("button", "scan-button", "Run CheckMate scan");
  run.type = "button";
  run.disabled = true;
  confirmation.addEventListener("change", () => {
    run.disabled = available.length === 0 || !confirmation.checked;
  });
  run.addEventListener("click", async () => {
    const profile = select.value;
    renderScanLoading(profile);
    try {
      const result = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({ profile }),
      });
      ui.state = result.state;
      toast("CheckMate report created. Preparing recommendations.");
      await runTriage();
    } catch (error) {
      ui.state.scanning = false;
      renderStartPage();
      toast(error.message, true);
    }
  });
  form.append(label, run);
  content.append(form);
  if (!available.length) {
    content.append(
      node(
        "p",
        "scan-config-error",
        "No Auth0 profile is configured. Add the dev or production CheckMate credentials to .env, then restart the UI.",
      ),
    );
  } else {
    content.append(
      node(
        "p",
        "scan-note",
        "The scan is read-only. It does not change Auth0 settings.",
      ),
    );
  }
  if (ui.state.hasReport) {
    const cancel = node("button", "return-review-button", "Return to review");
    cancel.type = "button";
    cancel.addEventListener("click", renderPage);
    content.append(cancel);
  }
  page.append(content);
  byId("workspace").replaceChildren(page);
}

function addBulletList(parent, items) {
  const list = node("ul");
  for (const item of items) list.append(node("li", "", item));
  parent.append(list);
}

function findingForKey(key) {
  return ui.state.findings.find((finding) => finding.key === key);
}

function valueAt(source, dottedPath) {
  let current = source;
  for (const segment of dottedPath.split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function displayValue(value) {
  if (value === null) return "Not set";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  return String(value);
}

function removedCallbackUrl(change) {
  if (
    !Array.isArray(change.currentValue) ||
    !Array.isArray(change.targetValue)
  ) {
    return "Callback URL";
  }
  return (
    change.currentValue.find(
      (value) =>
        typeof value === "string" && !change.targetValue.includes(value),
    ) || "Callback URL"
  );
}

function callbackLabel(value) {
  try {
    return `${new URL(value).host} callback`;
  } catch {
    return "Callback URL";
  }
}

function closePlanReview() {
  byId("plan-modal-overlay")?.remove();
}

function artifactUrl(profile, artifact, download = false) {
  const parameters = new URLSearchParams({ profile, artifact });
  if (download) parameters.set("download", "1");
  return `/api/artifact?${parameters.toString()}`;
}

function closeArtifactPreview() {
  byId("artifact-modal-overlay")?.remove();
}

async function openArtifactPreview(profile, artifact, filename) {
  try {
    const response = await fetch(artifactUrl(profile, artifact));
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || "The generated file could not be opened.");
    }
    const content = await response.text();
    closeArtifactPreview();
    const overlay = node("div", "modal-overlay artifact-modal-overlay");
    overlay.id = "artifact-modal-overlay";
    const modal = node("section", "artifact-modal");
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "artifact-modal-title");
    const header = node("header", "artifact-modal-header");
    const title = node("div");
    title.append(
      node("div", "eyebrow", `${profile} generated output`),
      node("h2", "", filename),
    );
    title.querySelector("h2").id = "artifact-modal-title";
    const actions = node("div", "artifact-modal-actions");
    const download = node("a", "artifact-download-button", "Download");
    download.href = artifactUrl(profile, artifact, true);
    download.setAttribute("download", "");
    const close = node("button", "modal-close", "×");
    close.type = "button";
    close.setAttribute("aria-label", "Close file preview");
    close.addEventListener("click", closeArtifactPreview);
    actions.append(download, close);
    header.append(title, actions);
    const preview = node("pre", "artifact-preview");
    preview.append(node("code", "", content));
    modal.append(header, preview);
    overlay.append(modal);
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) closeArtifactPreview();
    });
    document.body.append(overlay);
    close.focus();
  } catch (error) {
    toast(error.message, true);
  }
}

function executionSummary(parent) {
  if (!ui.state.execution) return;
  const result = node(
    "section",
    `execution-result ${ui.state.execution.status}`,
  );
  result.append(
    node(
      "h3",
      "",
      ui.state.execution.operation === "rollback"
        ? ui.state.execution.status === "succeeded"
          ? "Rollback completed"
          : "Rollback stopped"
        : ui.state.execution.status === "succeeded"
          ? "Execution completed"
          : "Execution stopped",
    ),
  );
  if (ui.state.execution.error) {
    result.append(node("p", "", ui.state.execution.error));
  }
  for (const call of ui.state.execution.calls) {
    const row = node("div", "execution-call");
    row.append(
      node("code", "", call.endpoint),
      node(
        "span",
        `execution-status ${call.status}`,
        call.status.replaceAll("_", " "),
      ),
    );
    if (call.error) row.append(node("p", "", call.error));
    result.append(row);
  }
  parent.append(result);
}

function openPlanReview() {
  closePlanReview();
  const changePackage = ui.state.changePackage;
  if (!changePackage) return;
  const overlay = node("div", "modal-overlay");
  overlay.id = "plan-modal-overlay";
  const modal = node("section", "plan-modal");
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-labelledby", "plan-modal-title");
  const header = node("header", "plan-modal-header");
  const heading = node("div");
  heading.append(
    node("div", "eyebrow", "Dual-environment change package"),
    node("h2", "", "Review generated outputs"),
    node(
      "p",
      "",
      "Each accepted change has an official-provider Terraform implementation and a live-preflighted Management API PATCH plan for development and production.",
    ),
  );
  heading.querySelector("h2").id = "plan-modal-title";
  const close = node("button", "modal-close", "×");
  close.type = "button";
  close.setAttribute("aria-label", "Close plan review");
  close.addEventListener("click", closePlanReview);
  header.append(heading, close);
  modal.append(header);

  if (changePackage.dev.tenantDomain === changePackage.prod.tenantDomain) {
    modal.append(
      node(
        "p",
        "validation-error environment-isolation-warning",
        `Development and production currently point to the same tenant (${changePackage.dev.tenantDomain}). Configure a separate production profile before promotion.`,
      ),
    );
  }
  const credentialAccess = changePackage.prod.credentialAccess;
  if (credentialAccess?.status === "write_access_detected") {
    modal.append(
      node(
        "p",
        "validation-error credential-access-alert",
        credentialAccess.message,
      ),
    );
  } else if (credentialAccess?.status === "unverified") {
    modal.append(
      node("p", "credential-access-unverified", credentialAccess.message),
    );
  }

  const environments = node("div", "plan-calls environment-plans");
  for (const profile of ["dev", "prod"]) {
    const artifact = changePackage[profile];
    const section = node("section", "environment-plan");
    const environmentHeader = node("div", "environment-plan-header");
    const title = node("div");
    title.append(
      node("span", "environment-name", profile),
      node(
        "h3",
        "",
        profile === "dev" ? "Development tenant" : "Production tenant",
      ),
      node("p", "", artifact.tenantDomain),
    );
    const validations = node("div", "validation-badges");
    validations.append(
      node(
        "span",
        `validation-badge ${artifact.terraformValidation.valid ? "valid" : "invalid"}`,
        `Terraform ${artifact.terraformValidation.valid ? "plan validated" : "invalid"}`,
      ),
      node(
        "span",
        `validation-badge ${artifact.apiValidation.valid ? "valid" : "invalid"}`,
        `${profile === "prod" ? "Read-only API preflight" : "API preflight"} ${artifact.apiValidation.valid ? "passed" : "failed"}`,
      ),
    );
    environmentHeader.append(title, validations);
    section.append(environmentHeader);
    const files = node("div", "artifact-files");
    for (const [kind, filename] of [
      ["terraform", artifact.terraformFile],
      ["api", artifact.apiFile],
      ["shell", artifact.shellFile],
    ]) {
      const row = node("div", "artifact-file");
      const view = node("button", "artifact-view-button", "View");
      view.type = "button";
      view.addEventListener("click", () =>
        openArtifactPreview(profile, kind, filename),
      );
      const download = node("a", "artifact-download-link", "Download");
      download.href = artifactUrl(profile, kind, true);
      download.setAttribute("download", "");
      const actions = node("div", "artifact-file-actions");
      actions.append(view, download);
      row.append(node("code", "", filename), actions);
      files.append(row);
    }
    section.append(files);
    section.append(
      node(
        "p",
        "artifact-digest",
        `API plan SHA-256: ${artifact.apiPlanSha256}`,
      ),
    );
    if (artifact.terraformValidation.error) {
      section.append(
        node(
          "p",
          "validation-error",
          `Terraform: ${artifact.terraformValidation.error}`,
        ),
      );
    }
    if (artifact.terraformCoverage.apiOnlyCalls.length) {
      const apiOnly = node("div", "validation-error");
      apiOnly.append(
        node(
          "p",
          "",
          `${artifact.terraformCoverage.managedCallIds.length} of ${artifact.plan.calls.length} API calls have an official Terraform deployment mapping.`,
        ),
      );
      for (const call of artifact.terraformCoverage.apiOnlyCalls) {
        apiOnly.append(node("p", "", `${call.resourceName}: ${call.reason}`));
      }
      section.append(apiOnly);
    }
    if (artifact.apiValidation.error) {
      section.append(
        node(
          "p",
          "validation-error",
          `API plan: ${artifact.apiValidation.error}`,
        ),
      );
    }
    if (!artifact.plan.calls.length) {
      section.append(
        node(
          "p",
          "empty-plan",
          "No API calls are required for this environment.",
        ),
      );
    }
    for (const call of artifact.plan.calls) {
      const card = node("article", "plan-call");
      const callTop = node("div", "plan-call-top");
      callTop.append(
        node("span", "method", call.method),
        node("code", "endpoint", call.endpoint),
      );
      card.append(callTop, node("h3", "", call.resourceName));
      const changes = node("div", "plan-changes");
      for (const precondition of call.preconditions) {
        const change = node("div", "plan-change");
        change.append(
          node("code", "", precondition.path),
          node(
            "span",
            "",
            `${displayValue(precondition.expectedValue)} → ${displayValue(valueAt(call.body, precondition.path))}`,
          ),
        );
        changes.append(change);
      }
      card.append(changes);
      section.append(card);
    }
    const excluded =
      artifact.plan.unchangedActionIds.length +
      artifact.plan.alreadyCompliantActionIds.length;
    if (excluded) {
      section.append(
        node(
          "p",
          "unchanged-count",
          `${artifact.plan.unchangedActionIds.length} left unchanged; ${artifact.plan.alreadyCompliantActionIds.length} already compliant.`,
        ),
      );
    }
    if (profile === "prod") {
      section.append(
        node(
          "p",
          "production-note",
          "Production outputs are for the formal change process. This POC cannot execute them.",
        ),
      );
    }
    environments.append(section);
  }
  modal.append(environments);
  executionSummary(modal);

  const footer = node("footer", "plan-modal-footer");
  const cancel = node("button", "modal-cancel", "Close");
  cancel.type = "button";
  cancel.addEventListener("click", closePlanReview);
  footer.append(cancel);
  if (ui.state.canExecute) {
    const confirmation = node("label", "execute-confirmation");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    confirmation.append(
      checkbox,
      node(
        "span",
        "",
        ui.state.execution?.operation === "apply" &&
          ui.state.execution.status === "failed"
          ? "I reviewed the completed calls and want to resume the remaining dev changes."
          : "I understand this will change the dev tenant.",
      ),
    );
    const resume =
      ui.state.execution?.operation === "apply" &&
      ui.state.execution.status === "failed";
    const execute = node(
      "button",
      "execute-button",
      resume ? "Resume changes" : "Execute changes",
    );
    execute.type = "button";
    execute.disabled = true;
    checkbox.addEventListener("change", () => {
      execute.disabled = !checkbox.checked;
    });
    execute.addEventListener("click", async () => {
      checkbox.disabled = true;
      execute.disabled = true;
      execute.textContent = "Executing…";
      try {
        const result = await api("/api/execute", {
          method: "POST",
          body: JSON.stringify({ confirmed: true }),
        });
        ui.state = result.state;
        renderSubmission();
        openPlanReview();
        toast(
          result.executed
            ? resume
              ? "Remaining Auth0 changes executed and verified."
              : "Auth0 changes executed and verified."
            : "Execution stopped. You can resume or roll back applied changes.",
          !result.executed,
        );
      } catch (error) {
        if (error.responseBody?.state) ui.state = error.responseBody.state;
        checkbox.disabled = false;
        execute.disabled = !checkbox.checked;
        execute.textContent = resume ? "Resume changes" : "Execute changes";
        toast(error.message, true);
      }
    });
    footer.append(confirmation, execute);
  } else if (
    changePackage.dev.plan.calls.length &&
    (!changePackage.dev.apiValidation.valid ||
      !changePackage.dev.terraformValidation.valid)
  ) {
    footer.append(
      node(
        "p",
        "execution-unavailable",
        "Dev execution is blocked until Terraform validation and the API preflight pass.",
      ),
    );
  }
  if (ui.state.canRollback) {
    const rollbackConfirmation = node("label", "execute-confirmation");
    const rollbackCheckbox = document.createElement("input");
    rollbackCheckbox.type = "checkbox";
    rollbackConfirmation.append(
      rollbackCheckbox,
      node(
        "span",
        "",
        "I reviewed the execution result and want to restore the applied dev settings.",
      ),
    );
    const rollback = node(
      "button",
      "rollback-button",
      "Roll back applied changes",
    );
    rollback.type = "button";
    rollback.disabled = true;
    rollbackCheckbox.addEventListener("change", () => {
      rollback.disabled = !rollbackCheckbox.checked;
    });
    rollback.addEventListener("click", async () => {
      rollbackCheckbox.disabled = true;
      rollback.disabled = true;
      rollback.textContent = "Rolling back…";
      try {
        const result = await api("/api/rollback", {
          method: "POST",
          body: JSON.stringify({ confirmed: true }),
        });
        ui.state = result.state;
        renderSubmission();
        openPlanReview();
        toast(
          result.rolledBack
            ? "Applied dev changes were rolled back and verified."
            : "Rollback stopped. Review the result and retry safely.",
          !result.rolledBack,
        );
      } catch (error) {
        if (error.responseBody?.state) ui.state = error.responseBody.state;
        rollbackCheckbox.disabled = false;
        rollback.disabled = !rollbackCheckbox.checked;
        rollback.textContent = "Roll back applied changes";
        toast(error.message, true);
      }
    });
    footer.append(rollbackConfirmation, rollback);
  }
  modal.append(footer);
  overlay.append(modal);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closePlanReview();
  });
  document.body.append(overlay);
  close.focus();
}

function renderDecisionOptions(finding, adminNotes, selectionCheckboxes = []) {
  const options = node("div", "decision-options");
  const accepted =
    finding.decision === "approved" || finding.decision === "mixed";
  const unchangedSelected = finding.decision === "accepted_risk";
  const accept = node(
    "button",
    `decision accept${accepted ? " selected" : ""}`,
    accepted
      ? "✓ Selection saved"
      : finding.selectionMode === "applications"
        ? "Accept for selected applications"
        : finding.selectionMode === "connections"
          ? "Accept for selected connections"
          : finding.selectionMode === "changes"
            ? "Accept selected removals"
            : "Accept suggestion",
  );
  const unchanged = node(
    "button",
    `decision unchanged${unchangedSelected ? " selected" : ""}`,
    unchangedSelected ? "✓ Remains unchanged" : "Remain unchanged",
  );
  accept.type = "button";
  unchanged.type = "button";
  accept.addEventListener("click", () => {
    const rationale = adminNotes.value.trim();
    const selectedActionIds = selectionCheckboxes.length
      ? selectionCheckboxes
          .filter((checkbox) => checkbox.checked)
          .map((checkbox) => checkbox.value)
      : finding.actionableChanges.map((change) => change.actionId);
    if (selectedActionIds.length === 0) {
      toast(
        finding.selectionMode === "applications"
          ? "Select at least one application, or remain unchanged."
          : finding.selectionMode === "connections"
            ? "Select at least one connection, or remain unchanged."
            : "Select at least one callback URL, or remain unchanged.",
        true,
      );
      return;
    }
    saveDecision(
      finding,
      "approved",
      rationale,
      [accept, unchanged],
      selectedActionIds,
    );
  });
  unchanged.addEventListener("click", () => {
    const rationale = adminNotes.value.trim();
    saveDecision(finding, "accepted_risk", rationale, [accept, unchanged], []);
  });
  options.append(accept, unchanged);
  return options;
}

function createFindingCard(finding, index) {
  const displayTitle =
    finding.key === "applications-use-rs256"
      ? finding.title.replace(/\s+for$/, "")
      : finding.title;
  const card = node(
    "article",
    `finding-card${finding.reviewed ? " reviewed" : ""}`,
  );
  card.dataset.findingKey = finding.key;
  const top = node("div", "finding-top");
  top.append(node("span", "finding-number", String(index + 1)));
  if (finding.severity) {
    top.append(
      node(
        "span",
        `severity ${finding.severity.toLowerCase()}`,
        finding.severity,
      ),
    );
  }
  if (finding.points) {
    top.append(
      node(
        "span",
        "recommendation-points",
        `+${finding.points} ${finding.points === 1 ? "point" : "points"}`,
      ),
    );
  }
  if (finding.reviewed) top.append(node("span", "saved", "Decision saved"));
  card.append(top, node("h2", "validator-title", displayTitle));
  if (finding.validatorTitle && finding.validatorTitle !== displayTitle) {
    card.append(node("p", "validator-context", finding.validatorTitle));
  }

  const suggestion = node("section", "suggestion");
  suggestion.append(node("h3", "", "Recommended security change"));
  addBulletList(suggestion, finding.analysis.remediationConsiderations);
  const reason = node("div", "reason");
  reason.append(node("strong", "", "Why this matters"));
  addBulletList(reason, finding.analysis.whyItMatters);
  suggestion.append(reason);
  const selectionCheckboxes = [];
  if (
    finding.selectionMode === "applications" ||
    finding.selectionMode === "connections" ||
    finding.selectionMode === "changes"
  ) {
    const applications = node("fieldset", "application-selection");
    if (finding.actionableChanges.length > 3) {
      applications.classList.add("scrollable");
    }
    applications.append(
      node(
        "legend",
        "",
        finding.selectionMode === "applications"
          ? "Select applications"
          : finding.selectionMode === "connections"
            ? "Select connections"
            : "Select callback URLs",
      ),
    );
    const selected = new Set(finding.selectedActionIds || []);
    const selectableChanges = [...finding.actionableChanges].sort(
      (left, right) => {
        if (
          finding.selectionMode === "applications" ||
          finding.selectionMode === "connections"
        ) {
          return left.resourceName.localeCompare(right.resourceName);
        }
        return removedCallbackUrl(left).localeCompare(
          removedCallbackUrl(right),
        );
      },
    );
    for (const change of selectableChanges) {
      const label = node("label", "application-option");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = change.actionId;
      checkbox.checked = finding.reviewed
        ? selected.has(change.actionId)
        : finding.defaultSelected !== false;
      selectionCheckboxes.push(checkbox);
      const text = node("span", "application-option-text");
      if (finding.selectionMode === "changes") {
        const callbackUrl = removedCallbackUrl(change);
        text.append(
          node("strong", "", callbackLabel(callbackUrl)),
          node("small", "", callbackUrl),
        );
      } else {
        text.append(
          node("strong", "", change.resourceName),
          node(
            "small",
            "",
            `${displayValue(change.currentValue)} → ${displayValue(change.targetValue)}`,
          ),
        );
      }
      label.append(checkbox, text);
      applications.append(label);
    }
    suggestion.append(applications);
    if (!finding.reviewed && finding.defaultSelected === false) {
      suggestion.append(
        node(
          "p",
          "compatibility-selection-note",
          "Nothing is selected by default. Confirm application compatibility and choose the affected resources before accepting this suggestion.",
        ),
      );
    }
  } else {
    const exact = node("div", "exact-changes");
    exact.append(node("strong", "", "Exact configuration changes"));
    for (const change of finding.actionableChanges) {
      const item = node("div", "exact-change");
      item.append(
        node("span", "change-resource", change.resourceName),
        node("code", "change-path", change.configPath),
        node(
          "span",
          "change-values",
          `${JSON.stringify(change.currentValue)} → ${JSON.stringify(change.targetValue)}`,
        ),
      );
      exact.append(item);
    }
    suggestion.append(exact);
  }
  const notes = node("label", "admin-notes");
  notes.append(node("strong", "", "Admin notes"));
  const adminNotes = document.createElement("textarea");
  adminNotes.className = "admin-notes-input";
  adminNotes.maxLength = 4_000;
  adminNotes.rows = 3;
  adminNotes.placeholder = "Add context for this decision.";
  adminNotes.value = finding.adminNote || "";
  notes.append(adminNotes);
  card.append(
    suggestion,
    notes,
    renderDecisionOptions(finding, adminNotes, selectionCheckboxes),
  );
  return card;
}

function replaceCard(key) {
  const finding = findingForKey(key);
  if (!finding) return;
  const index = ui.state.findings.findIndex((item) => item.key === key);
  const next = createFindingCard(finding, index);
  const current = ui.cards.get(key);
  if (current) current.replaceWith(next);
  ui.cards.set(key, next);
}

function renderSubmission() {
  const current = byId("submission");
  if (!current) return;
  const panel = node("section", "submission-panel");
  panel.id = "submission";
  if (!ui.state.submissionReady) {
    const remaining = ui.state.progress.total - ui.state.progress.completed;
    panel.append(
      node("div", "eyebrow", "Submit change decisions"),
      node("h2", "", "Create the change package"),
      node(
        "p",
        "",
        `${ui.state.progress.completed} of ${ui.state.progress.total} recommendations reviewed. Save ${remaining} more ${remaining === 1 ? "decision" : "decisions"} to enable Submit.`,
      ),
    );
    const submit = node("button", "submit-button", "Submit");
    submit.type = "button";
    submit.disabled = true;
    panel.append(submit);
    current.replaceWith(panel);
    return;
  }
  if (ui.state.submitted) {
    panel.classList.add("submitted");
    panel.append(
      node("div", "submit-check", "✓"),
      node(
        "h2",
        "",
        ui.state.execution?.status === "succeeded"
          ? "Changes executed"
          : "Change package created",
      ),
      node(
        "p",
        "",
        ui.state.execution?.status === "succeeded"
          ? "The accepted Auth0 changes were applied and verified against the dev tenant."
          : "Executable Terraform and drift-bound API outputs passed validation for development and production. Review them before dev execution.",
      ),
      node("code", "yaml-file", ui.state.changePackage.directory),
    );
    const review = node(
      "button",
      "review-plan-button",
      "Review change package",
    );
    review.type = "button";
    review.addEventListener("click", openPlanReview);
    panel.append(review);
    current.replaceWith(panel);
    return;
  }
  panel.append(
    node("div", "eyebrow", "All decisions saved"),
    node("h2", "", "Create the change package"),
    node(
      "p",
      "",
      "Submit your decisions to generate official-provider Terraform and live-preflighted API plans for development and production. The package is released only when both formats pass validation.",
    ),
  );
  const submit = node("button", "submit-button", "Submit");
  submit.type = "button";
  submit.addEventListener("click", async () => {
    submit.disabled = true;
    submit.textContent = "Generating and validating…";
    try {
      ui.state = await api("/api/submit", {
        method: "POST",
        body: "{}",
      }).then((result) => result.state);
      renderSubmission();
      openPlanReview();
      toast("Development and production change outputs created.");
    } catch (error) {
      submit.disabled = false;
      submit.textContent = "Submit";
      toast(error.message, true);
    }
  });
  panel.append(submit);
  current.replaceWith(panel);
}

function renderTriageLoading() {
  renderProgress();
  byId("workspace").classList.remove("review-workspace");
  const page = node("section", "triage-page");
  page.append(
    node("div", "spinner", ""),
    node("h1", "", "Preparing CheckMate remediation guidance"),
    node(
      "p",
      "",
      `Reviewing ${findingScope()} and validating supported recommendations against live tenant settings.`,
    ),
  );
  byId("workspace").replaceChildren(page);
}

function postureRatingLabel(rating) {
  return `${rating.charAt(0).toUpperCase()}${rating.slice(1)}`;
}

function createPostureScores(className = "posture-scores") {
  const posture = ui.state.posture;
  const scores = node("div", className);
  if (!posture) return scores;
  const scoreCard = (label, snapshot, detail) => {
    const card = node("article", `posture-score ${snapshot.rating}`);
    const top = node("div", "posture-score-top");
    top.append(
      node("span", "posture-score-label", label),
      node(
        "span",
        `posture-rating ${snapshot.rating}`,
        postureRatingLabel(snapshot.rating),
      ),
    );
    const value = node("div", "posture-score-value");
    value.append(
      node("strong", "", String(snapshot.score)),
      node("span", "", "points"),
    );
    card.append(top, value, node("p", "", detail));
    return card;
  };
  scores.append(
    scoreCard("Current", posture.current, "Latest CheckMate evidence"),
    scoreCard(
      "Projected",
      posture.projected,
      posture.delta > 0
        ? `+${posture.delta} points from accepted suggestions`
        : "No score movement selected yet",
    ),
  );
  return scores;
}

function createPosturePanel() {
  const posture = ui.state.posture;
  const panel = node("section", "posture-panel");
  panel.id = "posture";
  if (!posture) return panel;

  const heading = node("div", "posture-heading");
  heading.append(
    node("div", "eyebrow", "Weighted security measurement"),
    node("h2", "", "Auth0 tenant configuration posture"),
    node(
      "p",
      "",
      "Current posture comes from the latest CheckMate report. Projected posture shows the effect of accepted suggestions before any tenant change is made.",
    ),
  );

  const scores = createPostureScores();

  const remaining = posture.projected.openControlCount || 0;
  const foot = node("div", "posture-foot");
  foot.append(
    node(
      "p",
      "",
      `Model ${posture.modelVersion}. ${posture.passedControlCount} of ${posture.catalogControlCount} scorable CheckMate validators passed. Red validators earn 5 points, yellow earn 3, and green earn 1.`,
    ),
    node(
      "p",
      "",
      `${posture.unscoredValidatorCount} blue informational or violet GenAI report validators are excluded from posture points.`,
    ),
    node(
      "p",
      "",
      remaining
        ? `${remaining} scorable validators remain open after the selected decisions.`
        : "All scorable CheckMate validators passed or are projected to pass.",
    ),
    node(
      "p",
      "",
      "Colour thresholds: Red below 60 points, Amber from 60 to 79, and Green from 80.",
    ),
    node(
      "p",
      "posture-caveat",
      "A validator's points move into the projection only when all supported changes for that validator are accepted.",
    ),
  );
  panel.append(heading, scores, foot);
  return panel;
}

function createPostureSidebar() {
  const sidebar = node("aside", "posture-sidebar");
  sidebar.id = "posture-sidebar";
  sidebar.setAttribute("aria-label", "Current and projected posture scores");
  sidebar.append(
    node("div", "eyebrow", "Posture scores"),
    createPostureScores("posture-sidebar-scores"),
  );
  return sidebar;
}

function createAdditionalControlsPanel() {
  const controls = (ui.state.posture?.projected?.openControls || []).filter(
    (control) => !control.recommendationAvailable,
  );
  if (!controls.length) return null;
  const panel = node("section", "additional-controls");
  panel.append(
    node("div", "eyebrow", "Additional recommendations"),
    node("h2", "", "Important controls to review separately"),
    node(
      "p",
      "additional-controls-intro",
      "These controls still affect tenant hardening, but they do not currently map to a safe deterministic API change. Review them against platform support and business requirements.",
    ),
  );
  const list = node("div", "additional-controls-list");
  for (const control of controls) {
    const item = node("article", "additional-control");
    const heading = node("div", "additional-control-heading");
    heading.append(
      node("h3", "", control.title),
      node("span", "additional-control-importance", control.importance),
    );
    item.append(
      heading,
      node("p", "", control.guidance),
      node("span", "manual-review-label", "Manual review"),
    );
    list.append(item);
  }
  panel.append(list);
  return panel;
}

function renderPosture() {
  const current = byId("posture");
  if (current) current.replaceWith(createPosturePanel());
  const sidebar = byId("posture-sidebar");
  if (sidebar) sidebar.replaceWith(createPostureSidebar());
}

function renderPage() {
  renderProgress();
  const workspace = byId("workspace");
  workspace.classList.add("review-workspace");
  workspace.replaceChildren();
  ui.cards.clear();
  const intro = node("section", "page-intro");
  intro.append(
    node("div", "eyebrow", "CheckMate remediation guidance"),
    node("h1", "", `${ui.state.findings.length} recommended changes`),
    node(
      "p",
      "",
      `The application evaluated ${findingScope()}. Supported recommendations were verified against your tenant's current configuration.`,
    ),
  );
  const scanAgain = node("button", "scan-again-button", "Run new scan");
  scanAgain.type = "button";
  scanAgain.addEventListener("click", renderStartPage);
  intro.append(scanAgain);
  const list = node("section", "findings");
  if (!ui.state.findings.length) {
    const empty = node("article", "finding-card empty-card");
    empty.append(
      node("h2", "validator-title", "No actionable recommendations are ready"),
      node(
        "p",
        "",
        "The report contains no supported automatic change for these findings. Review the remaining controls manually.",
      ),
    );
    list.append(empty);
  }
  for (const [index, finding] of ui.state.findings.entries()) {
    const card = createFindingCard(finding, index);
    ui.cards.set(finding.key, card);
    list.append(card);
  }
  const submission = node("section", "submission-panel");
  submission.id = "submission";
  const main = node("div", "review-main");
  main.append(intro, createPosturePanel(), list, submission);
  const additionalControls = createAdditionalControlsPanel();
  if (additionalControls) main.append(additionalControls);
  const layout = node("div", "review-layout");
  layout.append(main, createPostureSidebar());
  workspace.append(layout);
  renderSubmission();
}

async function runTriage() {
  renderTriageLoading();
  try {
    ui.state = await api("/api/triage", {
      method: "POST",
      body: "{}",
    });
    renderPage();
  } catch (error) {
    const page = node("section", "error-page");
    page.append(
      node("h1", "", "Recommendations could not be prepared"),
      node("p", "", error.message),
    );
    const retry = node("button", "decision unchanged", "Try again");
    retry.type = "button";
    retry.addEventListener("click", runTriage);
    page.append(retry);
    byId("workspace").replaceChildren(page);
  }
}

async function saveDecision(
  finding,
  status,
  rationale,
  buttons,
  selectedActionIds,
) {
  for (const button of buttons) button.disabled = true;
  try {
    ui.state = await api("/api/decision", {
      method: "POST",
      body: JSON.stringify({
        findingKey: finding.key,
        status,
        rationale,
        selectedActionIds,
      }),
    }).then((result) => result.state);
    renderProgress();
    renderPosture();
    replaceCard(finding.key);
    renderSubmission();
    toast("Decision saved.");
  } catch (error) {
    toast(error.message, true);
    for (const button of buttons) button.disabled = false;
  }
}

async function initialise() {
  try {
    ui.state = await api("/api/state");
    if (!ui.state.hasReport) renderStartPage();
    else if (ui.state.triaged) renderPage();
    else await runTriage();
  } catch (error) {
    const page = node("section", "error-page");
    page.append(
      node("h1", "", "Unable to load review"),
      node("p", "", error.message),
    );
    byId("workspace").replaceChildren(page);
  }
}

initialise();
