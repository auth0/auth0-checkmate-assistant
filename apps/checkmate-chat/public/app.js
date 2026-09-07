const state = {
  csrfToken: "",
  history: [],
  busy: false,
  lastQuestion: "",
  activeProfile: null,
  activeReportId: null,
  scanTargets: null,
  scanningProfile: null,
};

const conversation = document.querySelector("#conversation");
const welcome = document.querySelector("#welcome");
const form = document.querySelector("#chat-form");
const input = document.querySelector("#question");
const sendButton = document.querySelector("#send-button");
const clearButton = document.querySelector("#clear-button");
const scanDevButton = document.querySelector("#scan-dev");
const scanProdButton = document.querySelector("#scan-prod");
const starterButtons = [...document.querySelectorAll("[data-question]")];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function scanButton(profile) {
  return profile === "dev" ? scanDevButton : scanProdButton;
}

function syncControls() {
  const conversationAvailable = Boolean(state.activeReportId);
  input.disabled = state.busy || !conversationAvailable;
  sendButton.disabled = state.busy || !conversationAvailable;
  input.placeholder = conversationAvailable
    ? `Ask about the selected ${state.activeProfile} tenant…`
    : "Run CheckMate for dev or prod to begin";
  for (const button of starterButtons) {
    button.disabled = state.busy || !conversationAvailable;
  }
  for (const profile of ["dev", "prod"]) {
    const button = scanButton(profile);
    const configured = state.scanTargets?.[profile]?.configured ?? false;
    button.disabled = state.busy || !configured;
    button.classList.toggle("running", state.scanningProfile === profile);
  }
}

function configureScanButton(profile, target) {
  const detail = document.querySelector(`#scan-${profile}-detail`);
  if (!target?.configured) {
    detail.textContent = "Not configured in .env";
    return;
  }
  detail.textContent = `${target.tenantDomain} · ${profile === "dev" ? "confirmed changes supported" : "conversation only"}`;
}

function renderOfficialAuth0McpStatus(auth0) {
  const statusNode = document.querySelector("#official-auth0-mcp-status");
  statusNode.classList.remove("pending", "connected", "unavailable");
  const connected = Boolean(auth0?.connected);
  statusNode.classList.add(connected ? "connected" : "unavailable");
  const statusText = connected ? "Connected · read-only" : "Not connected";
  statusNode.querySelector("strong").textContent = statusText;
  statusNode.setAttribute(
    "aria-label",
    `Official Auth0 MCP status: ${statusText}`,
  );
  const purpose =
    "Optional. It enriches answers with read-only live context but is not required for scanning, report interpretation, or confirmed dev remediation.";
  document.querySelector("#official-auth0-mcp-tooltip").textContent = connected
    ? `${purpose} It is currently connected with the enforced read-only tool allowlist.`
    : `${purpose} To connect it, run npx @auth0/auth0-mcp-server init --read-only, then restart the chatbot.`;
  statusNode.removeAttribute("title");
}

function renderAiProviderStatus(provider, model) {
  const labels = {
    openai: "OpenAI",
    anthropic: "Anthropic Claude",
    google: "Google Gemini",
  };
  const node = document.querySelector("#ai-provider-status");
  node.textContent = `AI: ${labels[provider] ?? provider} · ${model} · BYO credentials`;
  node.title =
    "The application operator supplies these credentials. They stay on the server and are never sent to the browser. Remediation does not use AI.";
}

function renderSelectedReport(report, environment) {
  state.activeProfile = environment?.profile ?? null;
  state.activeReportId = report?.reportId ?? null;
  if (!report || !environment) {
    document.querySelector("#report-title").textContent = "Choose a tenant";
    document.querySelector("#report-detail").textContent =
      "Run a new CheckMate assessment before starting the conversation.";
    syncControls();
    return;
  }
  document.querySelector("#report-title").textContent =
    `${environment.profile.toUpperCase()} · ${environment.tenantDomain}`;
  const details = [report.reportId];
  if (report.generatedAt) {
    const generated = new Date(report.generatedAt);
    details.push(
      Number.isNaN(generated.getTime())
        ? report.generatedAt
        : generated.toLocaleString(),
    );
  }
  if (report.counts) {
    details.push(
      `${report.counts.failed} failed`,
      `${report.counts.warning} warnings`,
    );
  }
  details.push(
    environment.profile === "dev"
      ? "confirmed changes supported"
      : "conversation only",
  );
  document.querySelector("#report-detail").textContent = details.join(" · ");
  syncControls();
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("Status could not be loaded.");
    const status = await response.json();
    state.csrfToken = status.csrfToken;
    renderOfficialAuth0McpStatus(status.auth0);
    renderAiProviderStatus(status.aiProvider, status.model);
    state.scanTargets = status.scanTargets;
    configureScanButton("dev", status.scanTargets.dev);
    configureScanButton("prod", status.scanTargets.prod);
    renderSelectedReport(status.report, status.activeEnvironment);
    const remediation = document.querySelector("#remediation-link");
    remediation.href = status.remediationUrl;
  } catch (error) {
    document.querySelector("#report-title").textContent = "Chatbot unavailable";
    document.querySelector("#report-detail").textContent = error.message;
    state.scanTargets = null;
    renderOfficialAuth0McpStatus({ connected: false });
    document.querySelector("#ai-provider-status").textContent =
      "AI provider unavailable";
    syncControls();
  }
}

function resizeInput() {
  input.style.height = "auto";
  input.style.height = `${Math.min(input.scrollHeight, 130)}px`;
}

function scrollToLatest() {
  window.requestAnimationFrame(() => {
    window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });
  });
}

function addUserMessage(question) {
  conversation.append(element("div", "message-user", question));
}

function addLoading() {
  const card = element("div", "loading-card");
  card.id = "active-loading";
  const row = element("div", "loading-row");
  row.append(element("span", "loading-orb"));
  const copy = element("div");
  copy.append(element("strong", "", "Reading CheckMate evidence"));
  copy.append(
    element(
      "small",
      "",
      "Selecting the report findings that answer your question.",
    ),
  );
  row.append(copy);
  card.append(row);
  conversation.append(card);

  const stages = [
    [
      "Reading CheckMate evidence",
      "Selecting the report findings that answer your question.",
    ],
    [
      "Checking available context",
      "Using live Auth0 data only when it closes an evidence gap.",
    ],
    [
      "Preparing a grounded answer",
      "Separating report facts from general guidance.",
    ],
  ];
  let index = 0;
  const timer = window.setInterval(() => {
    index = Math.min(index + 1, stages.length - 1);
    copy.querySelector("strong").textContent = stages[index][0];
    copy.querySelector("small").textContent = stages[index][1];
  }, 2800);
  return () => {
    window.clearInterval(timer);
    card.remove();
  };
}

const basisLabels = {
  checkmate_report: ["Report evidence", "basis basis-report"],
  auth0_live: ["Auth0 live", "basis basis-live"],
  general_guidance: ["Guidance", "basis basis-guidance"],
};

function addNextActionQuestion(card) {
  const next = element("section", "next-action-question");
  next.append(
    element(
      "strong",
      "",
      "There are other actions we can review to harden the tenant. Would you like to see the next recommendation?",
    ),
  );
  const nextControls = element("div", "next-action-controls");
  const continueButton = element(
    "button",
    "action-accept",
    "Show the next recommendation",
  );
  continueButton.type = "button";
  continueButton.addEventListener("click", () =>
    ask(
      "Show only the next highest-priority, low-friction hardening action from the CheckMate report. Do not repeat an action already reviewed.",
    ),
  );
  const stopButton = element("button", "action-decline", "Not now");
  stopButton.type = "button";
  stopButton.addEventListener("click", () => next.remove());
  nextControls.append(continueButton, stopButton);
  next.append(nextControls);
  card.append(next);
  scrollToLatest();
}

function answerAsHistory(answer) {
  const lines = [answer.headline];
  for (const section of answer.sections) {
    lines.push(section.title);
    for (const item of section.items) lines.push(`- ${item.text}`);
  }
  return lines.join("\n").slice(0, 4000);
}

function addAnswer(result) {
  const card = element("article", "answer-card");
  const head = element("div", "answer-head");
  head.append(element("div", "answer-label", "GROUNDED ANSWER"));
  head.append(element("h2", "", result.answer.headline));
  card.append(head);

  const body = element("div", "answer-body");
  for (const section of result.answer.sections) {
    const sectionNode = element("section", "answer-section");
    sectionNode.append(element("h3", "", section.title));
    const list = element("ul", "answer-list");
    for (const item of section.items) {
      const row = element("li");
      row.append(document.createTextNode(item.text));
      const [label, className] =
        basisLabels[item.basis] ?? basisLabels.general_guidance;
      row.append(element("span", className, label));
      list.append(row);
    }
    sectionNode.append(list);
    body.append(sectionNode);
  }
  card.append(body);

  const evidence = element("details", "evidence-drawer");
  evidence.append(element("summary", "", "Evidence and tools used"));
  const evidenceContent = element("div", "evidence-content");
  const list = element("dl");
  list.append(element("dt", "", "Report"));
  list.append(
    element(
      "dd",
      "",
      result.evidence.report?.reportId ?? "No report reference returned",
    ),
  );
  list.append(element("dt", "", "Evidence matched"));
  list.append(
    element(
      "dd",
      "",
      result.evidence.findingIds.length > 0
        ? `${result.evidence.findingIds.length} report ${result.evidence.findingIds.length === 1 ? "finding" : "findings"}`
        : "No individual finding was needed",
    ),
  );
  list.append(element("dt", "", "Lookups"));
  const tools = element("dd");
  const toolList = element("ul", "tool-list");
  for (const use of result.evidence.tools) {
    const tool = element("li", use.status === "failed" ? "failed" : "");
    tool.textContent = `${use.server} · ${use.tool}${use.status === "failed" ? " · failed" : ""}`;
    tool.title = use.error ?? `Retrieved ${use.retrievedAt}`;
    toolList.append(tool);
  }
  tools.append(toolList);
  list.append(tools);
  evidenceContent.append(list);
  evidence.append(evidenceContent);
  card.append(evidence);

  if (result.remediation?.actions?.length > 0) {
    const confirmations = element("section", "action-confirmations");
    confirmations.append(
      element("h3", "", "Would you like to take this action?"),
    );
    confirmations.append(
      element(
        "p",
        "",
        "Select a decision, then submit it. Nothing changes until the exact dev API call is reviewed and separately confirmed.",
      ),
    );
    for (const action of result.remediation.actions) {
      const row = element("div", "action-confirmation");
      row.append(element("strong", "", action.question));
      const controls = element("div", "action-confirmation-controls");
      const accept = element("button", "action-accept", "Accept suggestion");
      accept.type = "button";
      const decline = element("button", "action-decline", "Remain unchanged");
      decline.type = "button";
      controls.append(accept, decline);
      row.append(controls);
      const submit = element("button", "action-submit", "Submit decision");
      submit.type = "button";
      submit.hidden = true;
      let decision = "";
      const selectDecision = (selected) => {
        decision = selected;
        accept.classList.toggle("selected", selected === "accept");
        decline.classList.toggle("selected", selected === "unchanged");
        submit.hidden = false;
      };
      accept.addEventListener("click", () => selectDecision("accept"));
      decline.addEventListener("click", () => selectDecision("unchanged"));
      submit.addEventListener("click", async () => {
        if (!decision || submit.disabled) return;
        accept.disabled = true;
        decline.disabled = true;
        submit.disabled = true;
        submit.textContent = "Decision submitted";
        state.history.push({
          role: "user",
          content:
            decision === "accept"
              ? `I accepted this recommendation: ${action.question}`
              : `I chose to leave this recommendation unchanged: ${action.question}`,
        });
        state.history = state.history.slice(-12);
        if (decision === "accept" && action.recommendationId) {
          await prepareDevPlan(
            card,
            {
              recommendationId: action.recommendationId,
            },
            () => addNextActionQuestion(card),
          );
        } else {
          addNextActionQuestion(card);
        }
      });
      row.append(submit);
      confirmations.append(row);
    }
    card.append(confirmations);
  }
  conversation.append(card);
  state.history.push({
    role: "assistant",
    content: answerAsHistory(result.answer),
  });
  state.history = state.history.slice(-12);
  return card;
}

function resetConversation() {
  state.history = [];
  state.lastQuestion = "";
  conversation.replaceChildren();
  welcome.hidden = false;
  input.value = "";
  resizeInput();
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": state.csrfToken,
    },
    body: JSON.stringify(body),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error ?? "The request failed.");
  return result;
}

async function runScan(profile) {
  if (state.busy) return;
  if (!state.csrfToken) await loadStatus();
  if (!state.scanTargets?.[profile]?.configured) return;
  state.busy = true;
  state.scanningProfile = profile;
  document.querySelector("#report-title").textContent =
    `Running CheckMate for ${profile.toUpperCase()}…`;
  document.querySelector("#report-detail").textContent =
    `Creating a new report for ${state.scanTargets[profile].tenantDomain}.`;
  syncControls();
  try {
    const result = await postJson("/api/scan", { profile });
    resetConversation();
    renderSelectedReport(result.report, result.activeEnvironment);
  } catch (error) {
    await loadStatus();
    if (!state.activeReportId) {
      document.querySelector("#report-title").textContent =
        "CheckMate scan failed";
    }
    document.querySelector("#report-detail").textContent = error.message;
  } finally {
    state.busy = false;
    state.scanningProfile = null;
    syncControls();
    if (state.activeReportId) input.focus();
  }
}

function requestPreview(call) {
  const request = [
    `${call.method} ${call.url}`,
    "Authorization: Bearer <management-api-token>",
    "Content-Type: application/json",
    "",
    call.body ? JSON.stringify(call.body, null, 2) : "<no PATCH required>",
  ].join("\n");
  return element("pre", "request-body", request);
}

function changeValue(value) {
  if (value === null || value === undefined) return "Not set";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function executionSummary(container, response) {
  const result = response.result;
  const succeeded = response.executed && result?.status === "succeeded";
  const summary = element(
    "div",
    `execution-result${succeeded ? "" : " failed"}`,
  );
  summary.append(
    element(
      "strong",
      "",
      succeeded
        ? `Dev changes were applied and verified on ${response.tenantDomain}.`
        : "Dev execution stopped before all changes were verified.",
    ),
  );
  if (result?.calls?.length) {
    const list = element("ul", "planned-changes");
    for (const call of result.calls) {
      list.append(
        element(
          "li",
          "",
          `${call.endpoint}: ${call.status} · correlation ${call.correlationId}`,
        ),
      );
    }
    summary.append(list);
  }
  if (result?.error) summary.append(element("div", "", result.error));
  container.append(summary);
}

function renderDevPlan(shell, plan, onResolved) {
  shell.replaceChildren();
  const head = element("div", "dev-plan-head");
  const heading = element("div");
  heading.append(element("div", "dev-plan-kicker", "DEV IMPLEMENTATION PLAN"));
  heading.append(
    element(
      "h3",
      "",
      plan.calls.length === 1
        ? "Review the exact API call"
        : `Review ${plan.calls.length} exact API calls`,
    ),
  );
  head.append(
    heading,
    element("span", "validated-badge", "Preflight validated"),
  );
  shell.append(head);

  const meta = element("div", "dev-plan-meta");
  const tenant = element("span");
  tenant.append(element("strong", "", "Tenant: "));
  tenant.append(document.createTextNode(plan.tenantDomain));
  const profile = element("span");
  profile.append(element("strong", "", "Environment: "));
  profile.append(document.createTextNode("DEV only"));
  const expires = element("span");
  expires.append(element("strong", "", "Expires: "));
  expires.append(
    document.createTextNode(new Date(plan.expiresAt).toLocaleTimeString()),
  );
  const digest = element("span");
  digest.title = plan.planSha256;
  digest.append(element("strong", "", "Plan: "));
  digest.append(document.createTextNode(`${plan.planSha256.slice(0, 16)}…`));
  meta.append(tenant, profile, expires, digest);
  shell.append(meta);

  for (const call of plan.calls) {
    const preview = element("section", "api-preview");
    const route = element("div", "api-route");
    route.append(element("span", "method-badge", call.method));
    route.append(element("span", "api-url", call.url));
    preview.append(route);
    preview.append(element("h4", "", call.resourceName));
    preview.append(element("div", "change-label", "Approved changes"));
    const changes = element("div", "approved-changes");
    for (const change of call.changes) {
      const item = element("div", "approved-change");
      item.append(element("strong", "", change.description));
      const detail = element("div", "change-detail");
      detail.append(element("code", "change-path", change.configPath));
      const values = element("span", "change-values");
      values.append(
        element("span", "change-before", changeValue(change.currentValue)),
        element("span", "change-arrow", "→"),
        element("span", "change-after", changeValue(change.targetValue)),
      );
      detail.append(values);
      item.append(detail);
      changes.append(item);
    }
    preview.append(changes);
    const exactRequest = document.createElement("details");
    exactRequest.className = "exact-request";
    const summary = document.createElement("summary");
    summary.textContent = "Exact API payload";
    exactRequest.append(summary, requestPreview(call));
    if (call.sensitiveValuesRedacted) {
      exactRequest.append(
        element(
          "p",
          "redaction-note",
          "Sensitive live values are hidden in this display. The confirmed request digest still covers the complete payload.",
        ),
      );
    }
    preview.append(exactRequest);
    shell.append(preview);
  }

  const confirmation = element("div", "dev-confirmation");
  confirmation.append(
    element(
      "p",
      "dev-warning",
      "Validate this change in a development environment first. Follow your production change management process before promoting it. Do not apply it directly to production.",
    ),
  );
  const checkLabel = element("label", "confirmation-check");
  const checkbox = element("input");
  checkbox.type = "checkbox";
  checkbox.disabled = !plan.executionEnabled;
  checkLabel.append(checkbox);
  checkLabel.append(
    document.createTextNode(
      `I reviewed the API call and understand it will change ${plan.tenantDomain}.`,
    ),
  );
  confirmation.append(checkLabel);
  const textLabel = element("label", "confirmation-field");
  textLabel.append(element("span", "", 'Type "EXECUTE DEV" to confirm'));
  const confirmationText = element("input");
  confirmationText.type = "text";
  confirmationText.disabled = !plan.executionEnabled;
  confirmationText.autocomplete = "off";
  confirmationText.spellcheck = false;
  textLabel.append(confirmationText);
  confirmation.append(textLabel);
  const actions = element("div", "dev-plan-actions");
  const execute = element(
    "button",
    "execute-dev",
    "Confirm and execute on dev",
  );
  execute.type = "button";
  execute.disabled = true;
  if (!plan.executionEnabled) {
    execute.title = "Dev execution is currently disabled.";
  }
  const cancel = element("button", "cancel-dev", "Do not execute");
  cancel.type = "button";
  const updateEnabled = () => {
    execute.disabled =
      !plan.executionEnabled ||
      !checkbox.checked ||
      confirmationText.value.trim() !== "EXECUTE DEV";
  };
  checkbox.addEventListener("change", updateEnabled);
  confirmationText.addEventListener("input", updateEnabled);
  cancel.addEventListener("click", () => {
    confirmation.replaceChildren(
      element(
        "div",
        "execution-result failed",
        "No change was made. This plan will expire automatically.",
      ),
    );
    onResolved();
  });
  execute.addEventListener("click", async () => {
    if (execute.disabled || state.busy) return;
    state.busy = true;
    execute.disabled = true;
    execute.textContent = "Revalidating and executing…";
    sendButton.disabled = true;
    try {
      const response = await postJson("/api/dev-execute", {
        planId: plan.planId,
        planSha256: plan.planSha256,
        confirmed: true,
        tenantDomain: plan.tenantDomain,
        confirmationText: confirmationText.value.trim(),
      });
      confirmation.replaceChildren();
      executionSummary(confirmation, response);
      onResolved();
    } catch (error) {
      execute.textContent = "Execution stopped";
      execute.disabled = true;
      confirmation.append(
        element(
          "div",
          "dev-plan-error",
          `${error.message} Ask the question again to create a fresh plan.`,
        ),
      );
    } finally {
      state.busy = false;
      syncControls();
      scrollToLatest();
    }
  });
  actions.append(cancel, execute);
  confirmation.append(actions);
  shell.append(confirmation);
}

async function prepareDevPlan(card, remediation, onResolved) {
  const shell = element("section", "dev-plan-shell");
  const loading = element("div", "dev-plan-loading");
  loading.append(element("span", "loading-orb"));
  loading.append(
    element(
      "span",
      "",
      "Reading the dev configuration and validating the exact API request…",
    ),
  );
  shell.append(loading);
  card.append(shell);
  scrollToLatest();
  try {
    const result = await postJson("/api/dev-plan", {
      recommendationId: remediation.recommendationId,
    });
    renderDevPlan(shell, result.plan, onResolved);
  } catch (error) {
    shell.replaceChildren(
      element(
        "div",
        "dev-plan-error",
        `No executable dev plan was created. ${error.message}`,
      ),
    );
  }
  scrollToLatest();
}

function addError(message, question) {
  const card = element("div", "error-card");
  card.append(element("strong", "", "I could not complete that answer"));
  card.append(element("span", "", message));
  const retry = element("button", "retry-button", "Try again");
  retry.type = "button";
  retry.addEventListener("click", () => {
    card.remove();
    ask(question, true);
  });
  card.append(retry);
  conversation.append(card);
}

async function ask(rawQuestion, retry = false) {
  const question = rawQuestion.trim();
  if (!question || state.busy) return;
  if (!state.csrfToken) {
    await loadStatus();
    if (!state.csrfToken) return;
  }
  if (!state.activeReportId) {
    document.querySelector("#report-detail").textContent =
      "Run CheckMate for dev or prod before asking a question.";
    return;
  }
  state.busy = true;
  state.lastQuestion = question;
  sendButton.disabled = true;
  welcome.hidden = true;
  if (!retry) {
    addUserMessage(question);
    state.history.push({ role: "user", content: question });
    state.history = state.history.slice(-12);
  }
  input.value = "";
  resizeInput();
  const stopLoading = addLoading();
  scrollToLatest();

  try {
    const historyForRequest = state.history.slice(0, -1);
    const response = await fetch("/api/chat", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": state.csrfToken,
      },
      body: JSON.stringify({ question, history: historyForRequest }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(body.error ?? "The chatbot request failed.");
    stopLoading();
    addAnswer(body);
  } catch (error) {
    stopLoading();
    addError(error.message, question);
  } finally {
    state.busy = false;
    syncControls();
    if (state.activeReportId) input.focus();
    scrollToLatest();
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  ask(input.value);
});

input.addEventListener("input", resizeInput);
input.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});

for (const button of starterButtons) {
  button.addEventListener("click", () => ask(button.dataset.question));
}

scanDevButton.addEventListener("click", () => runScan("dev"));
scanProdButton.addEventListener("click", () => runScan("prod"));

clearButton.addEventListener("click", () => {
  if (state.busy) return;
  resetConversation();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

syncControls();
loadStatus();
