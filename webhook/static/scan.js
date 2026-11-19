"use strict";

const form = document.getElementById("scan-form");
const key = document.getElementById("api-key");
const connect = document.getElementById("connect");
const environment = document.getElementById("environment");
const resource = document.getElementById("resource");
const run = document.getElementById("run-scan");
const inventory = document.getElementById("inventory");
const feedback = document.getElementById("feedback");
let targets = [];
let loading = false;
let submitting = false;
let inventoryRequest = 0;

function scope() {
  return form.elements.scope.value;
}

function updateControls() {
  const entireEnvironment = scope() === "environment";
  resource.disabled = loading || submitting || entireEnvironment || !targets.length;
  run.disabled = loading || submitting || !key.value || !environment.value ||
    !targets.length || (!entireEnvironment && !resource.value);
  environment.disabled = loading || submitting || environment.options.length < 2;
  connect.disabled = loading || submitting;
  key.disabled = submitting;
  for (const radio of form.elements.scope) radio.disabled = submitting;
  run.textContent = submitting ? "Submitting to Wiz..." : "Start manual scan";
}

function showFeedback(title, message, error = false, outcomes = []) {
  feedback.hidden = false;
  feedback.className = error ? "error" : "success";
  document.getElementById("feedback-title").textContent = title;
  document.getElementById("feedback-message").textContent = message;
  const list = document.getElementById("outcomes");
  list.replaceChildren();
  for (const outcome of outcomes) {
    const item = document.createElement("li");
    item.textContent = `${outcome.target.name} (${outcome.target.resource_id}, ` +
      `${outcome.target.region}): ${outcome.status} - ${outcome.message}`;
    list.append(item);
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    cache: "no-store",
    credentials: "omit",
    headers: { "Content-Type": "application/json", "X-API-Key": key.value },
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The server returned an unreadable response. Check Wiz before retrying.");
  }
  if (!response.ok && !Array.isArray(data.results)) {
    const detail = typeof data.detail === "string" ? data.detail :
      Array.isArray(data.detail) ? data.detail.map(item => item.msg).join("; ") : null;
    throw new Error(detail || "The request failed. Check Wiz before retrying.");
  }
  return data;
}

key.addEventListener("input", () => {
  inventoryRequest++;
  loading = false;
  targets = [];
  environment.replaceChildren(new Option("Connect to load environments", ""));
  resource.replaceChildren(new Option("Select an environment first", ""));
  updateControls();
});

connect.addEventListener("click", async () => {
  if (!key.reportValidity()) return;
  loading = true;
  targets = [];
  inventoryRequest++;
  const request = inventoryRequest;
  feedback.hidden = true;
  updateControls();
  try {
    const environments = await api("/api/v1/scan/environments");
    if (request !== inventoryRequest) return;
    environment.replaceChildren(new Option("Select an environment", ""));
    resource.replaceChildren(new Option("Select an environment first", ""));
    for (const item of environments) {
      environment.add(new Option(`${item.name} (${item.id})`, item.id));
    }
    if (!environments.length) {
      showFeedback("No environments found", "No AWS accounts are available in collected Wiz data.", true);
    }
  } catch (error) {
    if (request === inventoryRequest) showFeedback("Connection failed", error.message, true);
  } finally {
    if (request === inventoryRequest) {
      loading = false;
      updateControls();
    }
  }
});

environment.addEventListener("change", async () => {
  targets = [];
  resource.replaceChildren(new Option("Select a resource", ""));
  inventoryRequest++;
  const request = inventoryRequest;
  feedback.hidden = true;
  if (!environment.value) {
    updateControls();
    return;
  }
  loading = true;
  inventory.textContent = "Loading active EC2 instances from Wiz...";
  updateControls();
  try {
    const result = await api("/api/v1/scan/resources?environment=" +
      encodeURIComponent(environment.value));
    if (request !== inventoryRequest) return;
    targets = result;
    for (const target of targets) {
      resource.add(new Option(`${target.name} - ${target.resource_id} (${target.region})`, target.arn));
    }
    inventory.textContent = `${targets.length} active EC2 instance(s). ` +
      "Environment scans target all active instances at submission time. " +
      "Inactive and Auto Scaling representative records are excluded.";
    if (!targets.length) showFeedback("No scan targets", "No active EC2 instances were found.", true);
  } catch (error) {
    if (request === inventoryRequest) {
      inventory.textContent = "Resource lookup failed; no scan was started.";
      showFeedback("Cannot load resources", error.message, true);
    }
  } finally {
    if (request === inventoryRequest) {
      loading = false;
      updateControls();
    }
  }
});

for (const radio of form.elements.scope) radio.addEventListener("change", updateControls);
resource.addEventListener("change", updateControls);

form.addEventListener("submit", async event => {
  event.preventDefault();
  if (run.disabled || !form.reportValidity()) return;
  const entireEnvironment = scope() === "environment";
  const selected = targets.find(target => target.arn === resource.value);
  const description = entireEnvironment
    ? `ALL active EC2 instances in ${environment.selectedOptions[0].textContent}`
    : `${selected.name} (${selected.resource_id}, ${selected.region})`;
  if (!window.confirm(`Start a real Wiz security scan for ${description}?`)) return;
  submitting = true;
  updateControls();
  showFeedback("Submitting scan requests", "Waiting for Wiz to confirm acceptance. Do not submit again.");
  const payload = { environment: environment.value, scan_type: "full" };
  if (!entireEnvironment) payload.resource_id = selected.arn;
  try {
    const result = await api("/api/v1/scan/run", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const accepted = result.status === "submitted";
    showFeedback(
      accepted ? "Scan requests accepted by Wiz" : "Scan submission needs attention",
      `${result.message} Audit annotation: ${result.annotation_id}.`,
      !accepted,
      result.results,
    );
  } catch (error) {
    showFeedback("Scan not confirmed", `${error.message} Check Wiz before retrying.`, true);
  } finally {
    submitting = false;
    updateControls();
  }
});
