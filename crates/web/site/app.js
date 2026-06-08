import init, { scan, version } from './pkg/web.js';

const SAMPLE_INSECURE = `services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    environment:
      DB_PASSWORD: admin
    privileged: true
    cap_add:
      - SYS_ADMIN

  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: password
    network_mode: host
`;

const SAMPLE_SECURE = `services:
  web:
    image: nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    user: "10001"
    read_only: true
    ports:
      - "127.0.0.1:8080:80"
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
`;

const $ = (id) => document.getElementById(id);
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function render(reportJson) {
  const results = $("results");
  const findingsEl = $("findings");
  const verdictEl = $("verdict");
  const digestEl = $("digest");
  results.hidden = false;

  let report;
  try {
    report = JSON.parse(reportJson);
  } catch (e) {
    verdictEl.className = "verdict flagged";
    verdictEl.textContent = "Internal error parsing report";
    findingsEl.innerHTML = "";
    digestEl.textContent = "";
    return;
  }

  if (report.error) {
    verdictEl.className = "";
    verdictEl.textContent = "";
    findingsEl.innerHTML = `<div class="error">${escapeHtml(report.error)}</div>`;
    digestEl.textContent = "";
    return;
  }

  const core = report.core;
  const findings = core.findings || [];
  const v = core.verdict;
  const counts = v.counts;
  const flagged = v.status !== "cleared";

  verdictEl.className = "verdict " + (flagged ? "flagged" : "cleared");
  verdictEl.innerHTML =
    `<span>${flagged ? "⚠ FLAGGED-GAP" : "✓ CLEARED"}</span>` +
    `<span class="counts">C:${counts.critical} H:${counts.high} ` +
    `M:${counts.medium} L:${counts.low} I:${counts.info}</span>`;

  // findings come canonically ordered (severity desc) from the engine
  findingsEl.innerHTML = findings
    .map((f) => {
      const sev = f.severity.toLowerCase();
      return `<div class="finding ${sev}">
        <div class="row">
          <span class="badge ${sev}">${f.severity}</span>
          <span class="rule">${escapeHtml(f.rule_id)}</span>
        </div>
        <div class="msg">${escapeHtml(f.message)}</div>
        <div class="fix"><b>fix:</b> ${escapeHtml(f.remediation)}</div>
        <div class="controls">${escapeHtml(f.controls.join(", "))} · ${escapeHtml(f.evidence.join(", "))}</div>
      </div>`;
    })
    .join("");

  digestEl.innerHTML =
    `<b>report_digest:</b> ${escapeHtml(report.envelope.report_digest)}` +
    `<br /><span>Deterministic &amp; reproducible — same input always yields this digest.</span>`;
}

function runScan() {
  render(scan($("compose").value));
}

async function main() {
  await init();
  $("version").textContent = version();
  $("scan").addEventListener("click", runScan);
  $("load-insecure").addEventListener("click", () => {
    $("compose").value = SAMPLE_INSECURE;
    runScan();
  });
  $("load-secure").addEventListener("click", () => {
    $("compose").value = SAMPLE_SECURE;
    runScan();
  });
  $("clear").addEventListener("click", () => {
    $("compose").value = "";
    $("results").hidden = true;
  });

  // Prefill with the insecure example and scan so the page is alive on load.
  $("compose").value = SAMPLE_INSECURE;
  runScan();
}

main();
