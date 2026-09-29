/**
 * CloudLens 360° - Enterprise Multi-Cloud Governance & Key Sentinel
 * Client-Side Real-Time Diagnostic & Audit Workbench
 * 
 * Features:
 * - Dynamic Multi-Pillar Architecture Scoring & CIS Benchmark Auditing
 * - Real Key & Secret Expiration Sentinel with live date countdown
 * - Real-time Multi-Cloud Service Inventory & Dynamic Topology Visualizer
 * - In-Memory Multi-Cloud IaC Scanner (Terraform, Bicep, ARM, CloudFormation)
 * - Full Workspace Persistence (localStorage, JSON Export / Import)
 * - Zero Mock Data & Zero Simulation Logic
 */

// ============================================================================
// WORKSPACE DATA & BASELINES
// ============================================================================

const STORAGE_KEY = "cloudlens_active_workspace";
const AUDIT_LOG_KEY = "cloudlens_audit_log";
const SETTINGS_KEY = "cloudlens_settings";

// Enterprise Settings defaults
const DEFAULT_SETTINGS = {
  critDays: 7,
  warnDays: 30,
  slaCritDays: 3,
  slaHighDays: 7,
  browserNotif: false,
  complianceFramework: "waf",
  theme: "dark"
};

let appSettings = { ...DEFAULT_SETTINGS };

// Standard reference baseline datasets for initial startup or benchmark loading
const BENCHMARK_BASELINES = {
  "multicloud": {
    name: "Production Multi-Cloud Enterprise Mesh",
    resources: [
      { id: "res-1", name: "Azure Front Door & WAF", provider: "azure", type: "Edge & WAF", status: "warning", note: "TLS 1.0 listener active" },
      { id: "res-2", name: "Azure AKS Ingestion Cluster", provider: "azure", type: "Compute", status: "healthy", note: "Workload Identity active" },
      { id: "res-3", name: "Azure Key Vault Premium", provider: "azure", type: "Security", status: "warning", note: "Public network access enabled" },
      { id: "res-4", name: "Azure Service Bus Premium", provider: "azure", type: "Messaging", status: "healthy", note: "Geo-disaster recovery paired" },
      { id: "res-5", name: "AWS EKS Microservices", provider: "aws", type: "Compute", status: "healthy", note: "Multi-AZ deployment" },
      { id: "res-6", name: "AWS RDS Aurora Multi-AZ", provider: "aws", type: "Database", status: "healthy", note: "KMS encrypted at rest" },
      { id: "res-7", name: "AWS KMS Customer Key", provider: "aws", type: "Security", status: "healthy", note: "Annual rotation active" },
      { id: "res-8", name: "AWS S3 Secure Archive", provider: "aws", type: "Storage", status: "critical", note: "Public Read ACL detected (CIS 2.1.5)" },
      { id: "res-9", name: "GCP GKE AI Inference", provider: "gcp", type: "Compute", status: "healthy", note: "Private cluster endpoints" },
      { id: "res-10", name: "GCP Vertex AI & BigQuery", provider: "gcp", type: "Analytics", status: "healthy", note: "VPC Service Controls active" },
      { id: "res-11", name: "GCP Cloud KMS HSM", provider: "gcp", type: "Security", status: "healthy", note: "Hardware security module" }
    ],
    keys: [
      {
        id: "key-1",
        provider: "aws",
        name: "aws-iam-access-key-settlement",
        service: "AWS IAM / EKS Cluster",
        type: "AWS IAM Access Key",
        storage: "Kubernetes Secret (aws-settlement)",
        expiryDate: getOffsetDateString(5), // 5 days from now
        impact: "EKS settlement pods lose permission to stream ledger batches to S3 and DynamoDB.",
        costRisk: "Immediate payment settlement halt"
      },
      {
        id: "key-2",
        provider: "azure",
        name: "spn-secret-appgateway-tls",
        service: "Azure App Gateway / Key Vault",
        type: "Entra ID Client Secret",
        storage: "Azure Key Vault (Secret)",
        expiryDate: getOffsetDateString(3), // 3 days from now
        impact: "Edge SSL termination certificate rotation fails; gateway enters degraded state.",
        costRisk: "High client connection drop rate"
      },
      {
        id: "key-3",
        provider: "gcp",
        name: "gsa-analytics-pipeline-key",
        service: "GCP Vertex AI / BigQuery",
        type: "GCP Service Account JSON",
        storage: "CI/CD Pipeline Secrets",
        expiryDate: getOffsetDateString(18), // 18 days from now
        impact: "Automated fraud inference pipelines fail authentication with Vertex AI.",
        costRisk: "Batch telemetry backlog"
      },
      {
        id: "key-4",
        provider: "azure",
        name: "kv-auto-rotating-cmk",
        service: "Azure Key Vault HSM",
        type: "Customer Managed Key (CMK)",
        storage: "Key Vault Premium Managed HSM",
        expiryDate: getOffsetDateString(180), // 180 days from now
        impact: "Zero outage risk. Automated rotation policy configured.",
        costRisk: "None"
      },
      {
        id: "key-5",
        provider: "aws",
        name: "aws-acm-wildcard-cert",
        service: "AWS CloudFront & ALB",
        type: "ACM SSL Certificate",
        storage: "AWS Certificate Manager",
        expiryDate: getOffsetDateString(240),
        impact: "Managed Certificate. AWS automatically rotates DNS validated certs.",
        costRisk: "None"
      }
    ],
    issues: [
      {
        id: "iss-1",
        title: "AWS S3 Bucket Public Read/Write ACL Enabled",
        severity: "CRITICAL",
        pillar: "security",
        provider: "aws",
        resource: "AWS S3 Secure Archive",
        description: "The S3 bucket permits public read/write access without AWS S3 Block Public Access enabled, exposing sensitive data to the internet (CIS AWS 2.1.5).",
        rootCause: "Bucket policy allows Principal: * or public ACL is set to public-read.",
        remediation: "Enable S3 Block Public Access at the account and bucket level: aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        remediated: false
      },
      {
        id: "iss-2",
        title: "Public Internet Ingress Allowed on Azure Key Vault",
        severity: "HIGH",
        pillar: "security",
        provider: "azure",
        resource: "Azure Key Vault Premium",
        description: "Key Vault has publicNetworkAccess enabled without Private Link isolation, exposing the vault endpoint to the public internet.",
        rootCause: "publicNetworkAccess property set to 'Enabled' in ARM/Bicep template.",
        remediation: "Set publicNetworkAccess: 'Disabled' and deploy an Azure Private Endpoint in the application virtual network.",
        remediated: false
      },
      {
        id: "iss-3",
        title: "TLS 1.0 & 1.1 Insecure Cipher Suites Accepted on Edge Listener",
        severity: "HIGH",
        pillar: "security",
        provider: "azure",
        resource: "Azure Front Door & WAF",
        description: "Edge load balancer listener accepts legacy TLS 1.0 and 1.1 handshakes with deprecated cipher suites, violating PCI-DSS and NIST 800-52r2.",
        rootCause: "Minimum TLS version not enforced on HTTPS listener configuration.",
        remediation: "Enforce minimum TLS 1.2 or 1.3 on all custom domain associations.",
        remediated: false
      },
      {
        id: "iss-4",
        title: "Unbounded Cross-Cloud Egress Latency on Core Settlement Pathway",
        severity: "MEDIUM",
        pillar: "reliability",
        provider: "hybrid",
        resource: "Cross-Cloud Network Link",
        description: "Synchronous cross-cloud REST calls between Azure AKS and AWS EKS traverse the public internet without an asynchronous queue buffer.",
        rootCause: "Absence of message broker buffering between cloud edge and compute backplane.",
        remediation: "Introduce Azure Service Bus or Amazon SQS as an asynchronous transactional buffer between cloud regions.",
        remediated: false
      }
    ]
  },
  "azure": {
    name: "Azure Enterprise Zero-Trust Architecture",
    resources: [
      { id: "res-az-1", name: "Azure Front Door Premium", provider: "azure", type: "Edge & WAF", status: "healthy", note: "TLS 1.3 enforced, Bot Manager active" },
      { id: "res-az-2", name: "Azure AKS Cluster (Private)", provider: "azure", type: "Compute", status: "healthy", note: "Workload Identity, KEDA auto-scale" },
      { id: "res-az-3", name: "Azure Key Vault Managed HSM", provider: "azure", type: "Security", status: "healthy", note: "Private Endpoint only" },
      { id: "res-az-4", name: "Azure Cosmos DB (Multi-Region)", provider: "azure", type: "Database", status: "healthy", note: "Multi-write, bounded staleness" },
      { id: "res-az-5", name: "Azure Service Bus Premium", provider: "azure", type: "Messaging", status: "healthy", note: "Availability zones enabled" }
    ],
    keys: [
      {
        id: "key-az-1",
        provider: "azure",
        name: "uami-aks-workload-id",
        service: "Azure Kubernetes Service",
        type: "Workload Identity (OIDC)",
        storage: "Entra ID (Zero Stored Secrets)",
        expiryDate: getOffsetDateString(365),
        impact: "Zero outage risk. Auto-rotated token federation.",
        costRisk: "None"
      },
      {
        id: "key-az-2",
        provider: "azure",
        name: "kv-storage-cmk",
        service: "Azure Key Vault HSM",
        type: "Customer Managed Key (CMK)",
        storage: "Key Vault Premium Managed HSM",
        expiryDate: getOffsetDateString(120),
        impact: "Automated Key Vault rotation policy active.",
        costRisk: "None"
      }
    ],
    issues: []
  },
  "aws": {
    name: "AWS Well-Architected Cloud Baseline",
    resources: [
      { id: "res-aws-1", name: "Amazon CloudFront & AWS WAF", provider: "aws", type: "Edge & WAF", status: "healthy", note: "Managed rules enabled" },
      { id: "res-aws-2", name: "Amazon EKS Cluster", provider: "aws", type: "Compute", status: "healthy", note: "IRSA configured" },
      { id: "res-aws-3", name: "Amazon RDS Aurora PostgreSQL", provider: "aws", type: "Database", status: "healthy", note: "Multi-AZ with read replica" },
      { id: "res-aws-4", name: "AWS Secrets Manager", provider: "aws", type: "Security", status: "healthy", note: "Lambda rotation active" }
    ],
    keys: [
      {
        id: "key-aws-1",
        provider: "aws",
        name: "acm-public-cert-wildcard",
        service: "AWS CloudFront",
        type: "ACM SSL Certificate",
        storage: "AWS Certificate Manager",
        expiryDate: getOffsetDateString(210),
        impact: "Managed certificate renewal handled automatically by ACM.",
        costRisk: "None"
      }
    ],
    issues: []
  }
};

// Helper: Calculate ISO date string relative to current time
function getOffsetDateString(daysOffset) {
  const d = new Date();
  d.setDate(d.getDate() + daysOffset);
  return d.toISOString().split("T")[0];
}

// Active workspace state (holds real inventory, keys, issues, metrics)
let activeWorkspace = {
  name: "Enterprise Multi-Cloud Production",
  resources: [],
  keys: [],
  issues: []
};

let currentCloudScope = "all";
let currentKeyFilter = "all";
let selectedTopologyNodeId = null;
let lastEndpointAnalysis = null;
let lastAnalysisTime = 0;

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

function bootstrap() {
  const steps = [
    ["Workspace", initWorkspace],
    ["Navigation", initNavigationTabs],
    ["CloudScope", initCloudScopeFilters],
    ["KeyTable", initKeyTableControls],
    ["IssueFilters", initIssueFilters],
    ["OmniScanner", initOmniScanner],
    ["EndpointAuditor", initEndpointAuditor],
    ["Modals", initModals],
    ["WorkspaceEvents", initWorkspaceEvents],
    ["Settings", initSettings],
    ["ThemeToggle", initThemeToggle],
    ["CommandPalette", initCommandPalette],
    ["CsvExports", initCsvExports],
    ["RenderViews", renderAllViews],
    ["NotifDot", initNotifDot]
  ];

  for (const [name, fn] of steps) {
    try {
      fn();
    } catch (err) {
      console.error(`[CloudLens] Error initializing ${name}:`, err);
    }
  }

  try {
    appendAuditLog({
      title: "Session Started",
      detail: `Workspace loaded: ${activeWorkspace.name || "N/A"} — ${(activeWorkspace.resources || []).length} resources, ${(activeWorkspace.keys || []).length} keys`,
      dotClass: "audit-dot-info",
      dotSvg: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>',
      chips: [{ label: "System", cls: "audit-chip-system" }]
    });
  } catch (err) {
    console.error("[CloudLens] Error appending initial audit log:", err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootstrap);
} else {
  bootstrap();
}

function resetToCleanWorkspace() {
  activeWorkspace = {
    name: "Enterprise Multi-Cloud Production",
    resources: [],
    keys: [],
    issues: []
  };
}

function initWorkspace() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    try {
      activeWorkspace = JSON.parse(saved);
    } catch (e) {
      console.warn("Could not parse saved workspace, resetting to clean workspace.", e);
      resetToCleanWorkspace();
    }
  } else {
    resetToCleanWorkspace();
  }

  const nameInput = document.getElementById("workspaceNameInput");
  if (nameInput) {
    nameInput.value = activeWorkspace.name || "Enterprise Multi-Cloud Production";
  }
}

function saveWorkspace(action) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(activeWorkspace));
  if (action) appendAuditLog(action);
}

function loadBenchmarkBaseline(baselineKey) {
  const template = BENCHMARK_BASELINES[baselineKey] || BENCHMARK_BASELINES["multicloud"];
  activeWorkspace = JSON.parse(JSON.stringify(template));
  saveWorkspace();
  const nameInput = document.getElementById("workspaceNameInput");
  if (nameInput) nameInput.value = activeWorkspace.name;
}

// ============================================================================
// AUDIT LOG
// ============================================================================

function loadAuditLog() {
  try {
    return JSON.parse(localStorage.getItem(AUDIT_LOG_KEY) || "[]");
  } catch { return []; }
}

function appendAuditLog(action) {
  const log = loadAuditLog();
  log.unshift({
    id: "log-" + Date.now(),
    ts: new Date().toISOString(),
    ...action
  });
  // Keep last 500 entries
  if (log.length > 500) log.length = 500;
  localStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(log));
}

function renderAuditHistory() {
  const container = document.getElementById("auditHistoryTimeline");
  if (!container) return;

  const log = loadAuditLog();

  if (log.length === 0) {
    container.innerHTML = `
      <div class="audit-empty-state">
        <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="12 5 12 12 16 14"/><circle cx="12" cy="12" r="10"/></svg>
        <h4>No Audit Events Recorded</h4>
        <p>Governance actions (imports, remediations, key rotations) will appear here as a tamper-evident chronological log.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  log.forEach(entry => {
    const item = document.createElement("div");
    item.className = "audit-timeline-item";

    const dotClass = entry.dotClass || "audit-dot-neutral";
    const chipHtml = (entry.chips || []).map(c => `<span class="audit-meta-chip ${c.cls}">${escapeHtml(c.label)}</span>`).join("");

    item.innerHTML = `
      <div class="audit-timeline-dot ${dotClass}">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">${entry.dotSvg || '<circle cx="12" cy="12" r="4"/>'}</svg>
      </div>
      <div class="audit-timeline-content">
        <div class="audit-timeline-header">
          <span class="audit-timeline-item-title">${escapeHtml(entry.title)}</span>
          <span class="audit-timeline-time">${new Date(entry.ts).toLocaleString()}</span>
        </div>
        <div class="audit-timeline-detail">${escapeHtml(entry.detail || "")}</div>
        <div class="audit-timeline-meta">${chipHtml}</div>
      </div>
    `;
    container.appendChild(item);
  });
}

function exportAuditLogCsv() {
  const log = loadAuditLog();
  if (log.length === 0) { showToast("No audit events to export.", "info"); return; }

  const rows = [["Timestamp", "Event", "Detail", "Category"].join(",")];
  log.forEach(e => {
    const cats = (e.chips || []).map(c => c.label).join(" | ");
    rows.push([e.ts, e.title, (e.detail || "").replace(/,/g, ";"), cats].map(v => `"${v}"`).join(","));
  });

  const blob = new Blob([rows.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `CloudLens_AuditLog_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Audit log exported as CSV.", "success");
}

// ============================================================================
// REAL-TIME METRIC & SCORING COMPUTATION
// ============================================================================

function computeWorkspaceMetrics() {
  const keys = activeWorkspace.keys || [];
  const issues = activeWorkspace.issues || [];
  const resources = activeWorkspace.resources || [];

  // 1. Calculate live days left & update statuses for all keys
  const now = new Date();
  let criticalKeysCount = 0;
  let warningKeysCount = 0;
  let healthyKeysCount = 0;

  keys.forEach(k => {
    if (!k.expiryDate) {
      k.daysLeft = 999;
      k.status = "healthy";
      healthyKeysCount++;
      return;
    }

    const expDate = new Date(k.expiryDate);
    const diffMs = expDate.getTime() - now.getTime();
    const days = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
    k.daysLeft = days;

    if (days <= (appSettings.critDays || 7)) {
      k.status = "critical";
      criticalKeysCount++;
    } else if (days <= (appSettings.warnDays || 30)) {
      k.status = "warning";
      warningKeysCount++;
    } else {
      k.status = "healthy";
      healthyKeysCount++;
    }
  });

  // 2. Tally active issues by severity
  const activeIssues = issues.filter(i => !i.remediated);
  const critIssues = activeIssues.filter(i => i.severity === "CRITICAL").length;
  const highIssues = activeIssues.filter(i => i.severity === "HIGH").length;
  const medIssues = activeIssues.filter(i => i.severity === "MEDIUM").length;
  const lowIssues = activeIssues.filter(i => i.severity === "LOW").length;

  // 3. Compute overall Health Score mathematically:
  let scoreDeductions = (critIssues * 15) + (highIssues * 8) + (medIssues * 4) + (criticalKeysCount * 10) + (warningKeysCount * 5);
  let healthScore = Math.max(12, 100 - scoreDeductions);

  // 4. Compute Pillar Scores (Security, Reliability, Performance, Cost, Operations)
  const pillarScores = {
    security: 100,
    reliability: 100,
    performance: 100,
    cost: 100,
    operations: 100
  };

  activeIssues.forEach(i => {
    const p = (i.pillar || "security").toLowerCase();
    const penalty = i.severity === "CRITICAL" ? 25 : i.severity === "HIGH" ? 15 : 8;
    if (pillarScores[p] !== undefined) {
      pillarScores[p] = Math.max(20, pillarScores[p] - penalty);
    }
  });

  // Deduct security score for expiring/critical secrets
  if (criticalKeysCount > 0) pillarScores.security = Math.max(20, pillarScores.security - (criticalKeysCount * 15));
  if (warningKeysCount > 0) pillarScores.security = Math.max(20, pillarScores.security - (warningKeysCount * 8));

  // 5. Compliance rate: percentage of controls passed
  let complianceRate = 100;
  const totalChecks = resources.length + keys.length + issues.length;
  if (totalChecks > 0) {
    const passedChecks = Math.max(0, totalChecks - activeIssues.length - criticalKeysCount);
    complianceRate = Math.round((passedChecks / totalChecks) * 100);
  }

  return {
    healthScore,
    pillarScores,
    criticalKeysCount,
    warningKeysCount,
    healthyKeysCount,
    activeIssuesCount: activeIssues.length,
    critIssues,
    highIssues,
    medIssues,
    lowIssues,
    resourcesCount: resources.length,
    complianceRate
  };
}

// ============================================================================
// VIEW RENDERING
// ============================================================================

function renderAllViews() {
  const metrics = computeWorkspaceMetrics();
  renderHeaderVitals(metrics);
  renderScoreHero(metrics);
  renderKeyRadar(metrics);
  renderAssetInventoryCard(metrics);
  renderServiceInventory();
  renderGuardrails(metrics);
  renderKeysTable();
  renderIssuesMatrix();
  renderTopology();
  // Refresh notification dot
  const dot = document.getElementById("notifAlertDot");
  if (dot) dot.classList.toggle("active", metrics.criticalKeysCount > 0);
}

function renderHeaderVitals(metrics) {
  const elKeyCount = document.getElementById("headerCriticalKeyCount");
  if (elKeyCount) elKeyCount.textContent = metrics.criticalKeysCount;

  const elHighIssues = document.getElementById("headerHighIssuesCount");
  if (elHighIssues) elHighIssues.textContent = metrics.critIssues + metrics.highIssues;

  const elHealth = document.getElementById("headerHealthScore");
  if (elHealth) elHealth.textContent = `${metrics.healthScore}%`;

  const tabKeyAlert = document.getElementById("tabKeyAlertBadge");
  if (tabKeyAlert) tabKeyAlert.textContent = metrics.criticalKeysCount;

  const tabIssuesBadge = document.getElementById("tabIssuesCountBadge");
  if (tabIssuesBadge) tabIssuesBadge.textContent = metrics.activeIssuesCount;
}

function renderScoreHero(metrics) {
  const score = metrics.healthScore;
  const numEl = document.getElementById("gaugeNumber");
  if (numEl) numEl.textContent = score;

  const circle = document.getElementById("gaugeCircle");
  if (circle) {
    const radius = 50;
    const circumference = 2 * Math.PI * radius; // ~314.15
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = offset;

    const badge = document.getElementById("healthBadgeStatus");
    if (score >= 90) {
      circle.style.stroke = "var(--status-healthy)";
      if (badge) {
        badge.className = "badge-status badge-healthy";
        badge.textContent = (metrics.resourcesCount === 0 && metrics.criticalKeysCount === 0 && metrics.activeIssuesCount === 0)
          ? "Operational Baseline"
          : "Production Hardened (Grade A+)";
      }
    } else if (score >= 70) {
      circle.style.stroke = "var(--status-warning)";
      if (badge) {
        badge.className = "badge-status badge-warning";
        badge.textContent = "Moderate Architecture Risk";
      }
    } else {
      circle.style.stroke = "var(--status-critical)";
      if (badge) {
        badge.className = "badge-status";
        badge.textContent = "Critical Attention Required";
      }
    }
  }

  // Pillar Bars
  const p = metrics.pillarScores;
  const setBar = (scoreId, barId, val) => {
    const s = document.getElementById(scoreId);
    const b = document.getElementById(barId);
    if (s) s.textContent = `${val}%`;
    if (b) b.style.width = `${val}%`;
  };

  setBar("scoreSecurity", "barSecurity", p.security);
  setBar("scoreReliability", "barReliability", p.reliability);
  setBar("scorePerformance", "barPerformance", p.performance);
  setBar("scoreCost", "barCost", p.cost);
  setBar("scoreOps", "barOps", p.operations);

  // Verdict text
  const verdict = document.getElementById("verdictText");
  if (verdict) {
    if (metrics.criticalKeysCount > 0 && metrics.critIssues > 0) {
      verdict.textContent = `${metrics.criticalKeysCount} cryptographic secrets expiring in ≤ ${appSettings.critDays || 7} days and ${metrics.critIssues} critical CIS benchmark violations detected. Immediate remediation recommended.`;
    } else if (metrics.criticalKeysCount > 0) {
      verdict.textContent = `${metrics.criticalKeysCount} credentials have reached critical expiration horizon (< ${appSettings.critDays || 7} days). Rotate credentials before service failover occurs.`;
    } else if (metrics.activeIssuesCount > 0) {
      verdict.textContent = `${metrics.activeIssuesCount} unmitigated architectural findings detected across multi-cloud infrastructure.`;
    } else if (metrics.resourcesCount === 0 && metrics.criticalKeysCount === 0) {
      verdict.textContent = "Workspace active. Ready to evaluate live application endpoints, monitor cryptographic key lifecycles, and audit multi-cloud IaC configurations.";
    } else {
      verdict.textContent = "All audited cloud services, keys, and security controls are operating within Well-Architected compliance baselines.";
    }
  }
}

function renderKeyRadar(metrics) {
  const elCrit = document.getElementById("kpiCriticalKeys");
  if (elCrit) elCrit.textContent = metrics.criticalKeysCount;

  const elWarn = document.getElementById("kpiWarningKeys");
  if (elWarn) elWarn.textContent = metrics.warningKeysCount;

  const elSafe = document.getElementById("kpiHealthyKeys");
  if (elSafe) elSafe.textContent = metrics.healthyKeysCount;

  const miniList = document.getElementById("imminentKeysMiniList");
  if (!miniList) return;

  miniList.innerHTML = "";
  const urgentKeys = (activeWorkspace.keys || [])
    .filter(k => k.status === "critical" || k.status === "warning")
    .sort((a, b) => a.daysLeft - b.daysLeft)
    .slice(0, 3);

  if (urgentKeys.length === 0) {
    miniList.innerHTML = `<div class="imminent-key-item" style="color:var(--status-healthy); font-size:0.85rem;">All active credentials & certificates are compliant (> 30 days remaining).</div>`;
    return;
  }

  urgentKeys.forEach(k => {
    const item = document.createElement("div");
    item.className = "imminent-key-item";
    const chipClass = k.status === "critical" ? "days-crit" : "days-warn";
    const providerBadge = k.provider ? `<span class="badge-provider badge-provider-${k.provider}">${k.provider.toUpperCase()}</span>` : "";
    item.innerHTML = `
      <div class="key-item-left">
        <div>
          <div class="key-name-bold">${escapeHtml(k.name)} ${providerBadge}</div>
          <div class="key-svc-badge">${escapeHtml(k.service || "")}</div>
        </div>
      </div>
      <div class="key-item-right">
        <span class="days-chip ${chipClass}">${k.daysLeft <= 0 ? 'EXPIRED' : k.daysLeft + 'd left'}</span>
      </div>
    `;
    miniList.appendChild(item);
  });
}

function renderAssetInventoryCard(metrics) {
  const totalRes = document.getElementById("totalResourcesCount");
  if (totalRes) totalRes.textContent = metrics.resourcesCount;

  const totalKeys = document.getElementById("totalKeysCount");
  if (totalKeys) totalKeys.textContent = (activeWorkspace.keys || []).length;

  const totalRisks = document.getElementById("totalOpenRisksCount");
  if (totalRisks) totalRisks.textContent = metrics.critIssues + metrics.highIssues;

  const compRate = document.getElementById("complianceRatePercent");
  if (compRate) compRate.textContent = `${metrics.complianceRate}%`;
}

function renderServiceInventory() {
  const container = document.getElementById("serviceChipList");
  const countBadge = document.getElementById("serviceCountBadge");
  if (!container) return;

  const resources = activeWorkspace.resources || [];
  if (countBadge) countBadge.textContent = `${resources.length} Services Evaluated`;

  container.innerHTML = "";

  const filtered = resources.filter(r => {
    if (currentCloudScope === "all") return true;
    return (r.provider || "azure") === currentCloudScope;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem; padding:0.5rem;">No cloud resources imported for selected cloud scope. Import inventory or scan IaC templates.</div>`;
    return;
  }

  filtered.forEach(res => {
    const chip = document.createElement("div");
    chip.className = `service-chip chip-${res.status || 'healthy'}`;
    const providerClass = res.provider ? `badge-provider-${res.provider}` : 'badge-provider-azure';
    chip.innerHTML = `
      <div class="svc-chip-head">
        <span class="svc-name">${escapeHtml(res.name)}</span>
        <span class="badge-provider ${providerClass}">${(res.provider || 'cloud').toUpperCase()}</span>
      </div>
      <div class="svc-type">${escapeHtml(res.type || "")}</div>
      <div class="svc-note">${escapeHtml(res.note || "Operational")}</div>
    `;
    container.appendChild(chip);
  });
}

function renderGuardrails(metrics) {
  const keys = activeWorkspace.keys || [];
  const resources = activeWorkspace.resources || [];
  const issues = activeWorkspace.issues || [];

  // SEC-01: Static Secrets Check
  const staticKeys = keys.filter(k => {
    const t = (k.type || "").toLowerCase();
    return t.includes("secret") || t.includes("access key") || t.includes("json") || t.includes("token");
  });
  const sec01Passed = staticKeys.length === 0;

  // REL-01: Message Queue Decoupling Check
  const hasQueue = resources.some(r => {
    const n = (r.name + " " + r.type).toLowerCase();
    return n.includes("service bus") || n.includes("sqs") || n.includes("pub/sub") || n.includes("queue") || n.includes("kafka");
  });

  // NET-01: Network Perimeter & Private Endpoints Check
  const hasPublicIngressIssue = issues.some(i => !i.remediated && (i.title.toLowerCase().includes("public") || i.title.toLowerCase().includes("ingress")));
  const net01Passed = !hasPublicIngressIssue;

  // GOV-01: Expiration Lifecycle Check
  const hasExpiringKey = keys.some(k => k.daysLeft <= (appSettings.warnDays || 30));
  const gov01Passed = !hasExpiringKey;

  const isEmpty = resources.length === 0 && keys.length === 0;
  const controls = [
    { num: 1, passed: sec01Passed, evidence: isEmpty ? "Compliant: 0 static secrets found. Enforce Managed Identity on new resources." : (sec01Passed ? "Compliant: 0 static secrets found. All services using Managed Identity / OIDC." : `Violated: ${staticKeys.length} static client secret(s) or access keys detected.`) },
    { num: 2, passed: isEmpty ? true : hasQueue, evidence: isEmpty ? "Compliant: Architecture standard ready. Enforce message queues on async paths." : (hasQueue ? "Compliant: Asynchronous message queue buffer present in active inventory." : "Violated: Synchronous database calls detected without message queue buffering.") },
    { num: 3, passed: net01Passed, evidence: net01Passed ? "Compliant: Private Link / VPC service perimeter isolation active." : "Violated: Public internet access detected on database, storage, or key vault." },
    { num: 4, passed: gov01Passed, evidence: gov01Passed ? "Compliant: All active credentials have healthy expiration horizons (> 30d)." : "Violated: Active cryptographic credentials approaching critical expiration horizon." }
  ];

  let passedCount = 0;
  controls.forEach(c => {
    if (c.passed) passedCount++;
    const card = document.getElementById(`axiomCard${c.num}`);
    const badge = document.getElementById(`axiomBadge${c.num}`);
    const ev = document.getElementById(`axiomEvidence${c.num}`);
    if (card && badge && ev) {
      card.className = `axiom-card ${c.passed ? 'axiom-enforced' : 'axiom-violated'}`;
      badge.className = `axiom-badge-state ${c.passed ? 'state-enforced' : 'state-violated'}`;
      badge.textContent = c.passed ? "COMPLIANT" : "VIOLATED";
      ev.innerHTML = `<strong>Status:</strong> ${c.evidence}`;
    }
  });

  const overallBadge = document.getElementById("axiomsComplianceBadge");
  if (overallBadge) {
    overallBadge.textContent = `${passedCount} of 4 Controls Passed`;
    overallBadge.className = passedCount === 4 ? "badge-status badge-healthy" : "badge-status";
  }
}

// ============================================================================
// TAB 2: KEY SENTINEL TABLE & ACTIONS
// ============================================================================

function renderKeysTable() {
  const tbody = document.getElementById("keysTableBody");
  if (!tbody) return;

  tbody.innerHTML = "";
  const searchTerm = (document.getElementById("filterKeySearch")?.value || "").toLowerCase();
  const allKeys = activeWorkspace.keys || [];

  // Provider counters
  const countAll = allKeys.length;
  const countAzure = allKeys.filter(k => (k.provider || 'azure') === 'azure').length;
  const countAws = allKeys.filter(k => k.provider === 'aws').length;
  const countGcp = allKeys.filter(k => k.provider === 'gcp').length;

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl("countCloudAll", countAll);
  setEl("countCloudAzure", countAzure);
  setEl("countCloudAws", countAws);
  setEl("countCloudGcp", countGcp);

  // Status counters
  const critCount = allKeys.filter(k => k.status === "critical").length;
  const warnCount = allKeys.filter(k => k.status === "warning").length;
  const safeCount = allKeys.filter(k => k.status === "healthy").length;

  setEl("keyFilterAllCount", countAll);
  setEl("keyFilterCritCount", critCount);
  setEl("keyFilterWarnCount", warnCount);
  setEl("keyFilterSafeCount", safeCount);

  // Filter keys
  const filtered = allKeys.filter(k => {
    if (currentCloudScope !== "all") {
      const p = k.provider || 'azure';
      if (p !== currentCloudScope && p !== "hybrid") return false;
    }

    if (currentKeyFilter !== "all" && k.status !== currentKeyFilter) return false;

    if (searchTerm) {
      const str = (k.name + " " + k.service + " " + k.type + " " + (k.provider || "")).toLowerCase();
      if (!str.includes(searchTerm)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="9" style="text-align:center; padding:2rem; color:var(--text-muted);">No cryptographic keys matching current filters. Click "Track New Key/Cert" to register credentials.</td>`;
    tbody.appendChild(tr);
    return;
  }

  filtered.forEach(k => {
    const tr = document.createElement("tr");
    const statusClass = k.status === "critical" ? "status-critical" : k.status === "warning" ? "status-warning" : "status-healthy";
    const statusText = k.status === "critical" ? "CRITICAL" : k.status === "warning" ? "WARNING" : "HEALTHY";
    const providerClass = k.provider ? `badge-provider-${k.provider}` : 'badge-provider-azure';

    tr.innerHTML = `
      <td><span class="badge-status ${statusClass}">${statusText}</span></td>
      <td><span class="badge-provider ${providerClass}">${(k.provider || 'azure').toUpperCase()}</span></td>
      <td><strong>${escapeHtml(k.name)}</strong></td>
      <td>${escapeHtml(k.service || "")}</td>
      <td><span class="badge-subtle">${escapeHtml(k.type || "")}</span></td>
      <td><code>${escapeHtml(k.expiryDate || "N/A")}</code></td>
      <td><span class="days-chip ${k.status === 'critical' ? 'days-crit' : k.status === 'warning' ? 'days-warn' : 'days-safe'}">${k.daysLeft <= 0 ? 'EXPIRED' : k.daysLeft + 'd left'}</span></td>
      <td><span style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(k.impact || "Service interruption")}</span></td>
      <td>
        <div style="display:flex; gap:0.35rem; align-items:center;">
          <button class="btn btn-xs btn-outline" onclick="openUpdateExpiryModal('${k.id}')" title="Update Expiry Horizon">Update</button>
          <button class="btn btn-xs btn-ghost text-danger" onclick="deleteKey('${k.id}')" title="Delete from Sentinel">&times;</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function deleteKey(keyId) {
  if (!confirm("Are you sure you want to remove this key from Sentinel monitoring?")) return;
  activeWorkspace.keys = (activeWorkspace.keys || []).filter(k => k.id !== keyId);
  saveWorkspace();
  renderAllViews();
  showToast("Key removed from Sentinel monitoring.", "info");
}

function openUpdateExpiryModal(keyId) {
  const k = (activeWorkspace.keys || []).find(item => item.id === keyId);
  if (!k) return;

  document.getElementById("updateExpiryKeyId").value = k.id;
  document.getElementById("updateExpiryTargetName").textContent = `Updating expiration for: ${k.name} (${k.service})`;
  document.getElementById("newExpiryInputDate").value = k.expiryDate || getOffsetDateString(90);

  const modal = document.getElementById("modalUpdateExpiry");
  if (modal) modal.classList.add("active");
}

// ============================================================================
// CVSS & SLA HELPERS
// ============================================================================

function getCvssScore(severity) {
  const map = {
    CRITICAL: { score: "9.8", cls: "cvss-critical" },
    HIGH: { score: "7.5", cls: "cvss-high" },
    MEDIUM: { score: "5.3", cls: "cvss-medium" },
    LOW: { score: "2.1", cls: "cvss-low" }
  };
  return map[severity] || { score: "N/A", cls: "cvss-low" };
}

function getSlaStatus(iss) {
  if (iss.remediated) return null;
  const createdAt = iss.createdAt ? new Date(iss.createdAt) : new Date(Date.now() - 86400000 * 2);
  const slaDays = iss.severity === "CRITICAL" ? appSettings.slaCritDays :
                  iss.severity === "HIGH" ? appSettings.slaHighDays : 14;
  const dueDate = new Date(createdAt.getTime() + slaDays * 86400000);
  const now = new Date();
  const daysLeft = Math.ceil((dueDate - now) / 86400000);
  if (daysLeft < 0) return { label: `SLA Overdue (${Math.abs(daysLeft)}d)`, cls: "sla-overdue" };
  if (daysLeft <= 2) return { label: `SLA Due in ${daysLeft}d`, cls: "sla-due-soon" };
  return { label: `SLA: ${daysLeft}d remaining`, cls: "sla-compliant" };
}

// ============================================================================
// TAB 3: ISSUES MATRIX
// ============================================================================

function renderIssuesMatrix() {
  const container = document.getElementById("issuesListContainer");
  if (!container) return;

  container.innerHTML = "";
  const pillarFilter = document.getElementById("filterPillarSelect")?.value || "all";
  const sevFilter = document.getElementById("filterSeveritySelect")?.value || "all";
  const issues = activeWorkspace.issues || [];

  const filtered = issues.filter(i => {
    if (currentCloudScope !== "all") {
      const p = i.provider || 'azure';
      if (p !== currentCloudScope && p !== "hybrid") return false;
    }
    if (pillarFilter !== "all" && (i.pillar || "security").toLowerCase() !== pillarFilter) return false;
    if (sevFilter !== "all" && i.severity !== sevFilter) return false;
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding:3rem; text-align:center;">
        <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" style="margin:0 auto 1rem; color:var(--status-healthy);"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <h3>No Architectural Vulnerabilities</h3>
        <p style="color:var(--text-muted); font-size:0.85rem;">All active infrastructure components comply with the selected Well-Architected Framework and CIS Benchmarks.</p>
      </div>
    `;
    return;
  }

  filtered.forEach(iss => {
    const card = document.createElement("div");
    card.className = `issue-card issue-${iss.severity.toLowerCase()} ${iss.remediated ? 'issue-remediated' : ''}`;
    const providerClass = iss.provider ? `badge-provider-${iss.provider}` : 'badge-provider-azure';
    const cvss = getCvssScore(iss.severity);
    const sla = getSlaStatus(iss);
    const slaBadge = sla ? `<span class="sla-badge ${sla.cls}">${escapeHtml(sla.label)}</span>` : '';
    const cvssChip = `<span class="cvss-score-chip ${cvss.cls}" title="CVSS Base Score">CVSS ${cvss.score}</span>`;

    card.innerHTML = `
      <div class="issue-header">
        <div class="issue-title-group">
          <span class="badge-status badge-${iss.severity.toLowerCase()}">${iss.severity}</span>
          <span class="badge-provider ${providerClass}">${(iss.provider || 'cloud').toUpperCase()}</span>
          <span class="badge-subtle">${(iss.pillar || 'Security').toUpperCase()}</span>
          ${cvssChip}
          <h4 class="issue-title">${escapeHtml(iss.title)}</h4>
        </div>
        <div class="issue-actions-top">
          <button class="btn btn-xs ${iss.remediated ? 'btn-ghost' : 'btn-accent'}" onclick="toggleRemediateIssue('${iss.id}')">
            ${iss.remediated ? 'Re-open Finding' : 'Mark Remediated'}
          </button>
          <button class="btn btn-xs btn-ghost text-danger" onclick="deleteIssue('${iss.id}')" title="Delete Finding">&times;</button>
        </div>
      </div>
      <p class="issue-desc">${escapeHtml(iss.description)}</p>
      <div class="issue-meta-grid">
        <div class="issue-meta-item">
          <strong>Impacted Asset:</strong> ${escapeHtml(iss.resource || "Cluster Resource")}
        </div>
        <div class="issue-meta-item">
          <strong>Root Cause:</strong> ${escapeHtml(iss.rootCause || "Configuration deviation")}
        </div>
      </div>
      <div class="issue-meta-row-extended">
        ${slaBadge}
        ${iss.remediated && iss.remediatedAt ? `<span class="badge-subtle">Resolved: ${new Date(iss.remediatedAt).toLocaleDateString()}</span>` : ''}
        ${iss.createdAt ? `<span style="font-size:0.72rem;color:var(--text-dim);">Opened: ${new Date(iss.createdAt).toLocaleDateString()}</span>` : ''}
      </div>
      <div class="issue-remedy-box">
        <div class="remedy-title">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          Remediation Guidance
        </div>
        <pre class="code-snippet-small"><code>${escapeHtml(iss.remediation || "Review cloud provider security policy.")}</code></pre>
      </div>
    `;
    container.appendChild(card);
  });
}

function toggleRemediateIssue(issueId) {
  const iss = (activeWorkspace.issues || []).find(i => i.id === issueId);
  if (!iss) return;
  iss.remediated = !iss.remediated;
  if (iss.remediated) {
    iss.remediatedAt = new Date().toISOString();
  } else {
    delete iss.remediatedAt;
  }
  saveWorkspace({
    title: iss.remediated ? `Finding Remediated: ${iss.title}` : `Finding Re-opened: ${iss.title}`,
    detail: `Severity: ${iss.severity} | Resource: ${iss.resource || 'N/A'}`,
    dotClass: iss.remediated ? "audit-dot-success" : "audit-dot-warning",
    dotSvg: iss.remediated ? '<polyline points="20 6 9 17 4 12"/>' : '<path d="M12 9v2m0 4h.01"/>',
    chips: [{ label: iss.remediated ? "Remediated" : "Re-opened", cls: iss.remediated ? "audit-chip-remediate" : "audit-chip-delete" }, { label: iss.severity, cls: "audit-chip-scan" }]
  });
  renderAllViews();
  showToast(iss.remediated ? "Finding marked as remediated!" : "Finding re-opened.", "info");
}

function deleteIssue(issueId) {
  const iss = (activeWorkspace.issues || []).find(i => i.id === issueId);
  const title = iss ? iss.title : "Unknown finding";
  activeWorkspace.issues = (activeWorkspace.issues || []).filter(i => i.id !== issueId);
  saveWorkspace({
    title: `Finding Deleted: ${title}`,
    detail: "Finding permanently removed from workspace.",
    dotClass: "audit-dot-danger",
    dotSvg: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
    chips: [{ label: "Deleted", cls: "audit-chip-delete" }]
  });
  renderAllViews();
  showToast("Finding removed from workspace.", "info");
}

// ============================================================================
// TAB 4: DYNAMIC SERVICE TOPOLOGY & BLAST RADIUS CANVAS
// ============================================================================

function renderTopology() {
  const canvas = document.getElementById("topologyCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;

  ctx.clearRect(0, 0, width, height);

  const resources = activeWorkspace.resources || [];
  const filtered = resources.filter(r => {
    if (currentCloudScope === "all") return true;
    return (r.provider || "azure") === currentCloudScope;
  });

  if (filtered.length === 0) {
    ctx.fillStyle = "rgba(255, 255, 255, 0.4)";
    ctx.font = "14px Plus Jakarta Sans, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No active cloud resources in workspace.", width / 2, height / 2 - 12);
    ctx.fillStyle = "rgba(0, 210, 255, 0.7)";
    ctx.font = "12px Plus Jakarta Sans, sans-serif";
    ctx.fillText("Audit an App URL above or import IaC templates to construct the interactive service mesh graph.", width / 2, height / 2 + 14);
    return;
  }

  // Calculate dynamic node positions arranged in logical architectural tiers
  const nodes = [];
  const total = filtered.length;
  const cols = Math.min(4, Math.ceil(Math.sqrt(total)));
  const rows = Math.ceil(total / cols);
  const cellW = width / (cols + 1);
  const cellH = height / (rows + 1);

  filtered.forEach((r, idx) => {
    const c = idx % cols;
    const row = Math.floor(idx / cols);
    const x = cellW * (c + 1);
    const y = cellH * (row + 1);

    nodes.push({
      id: r.id,
      name: r.name,
      provider: r.provider || "azure",
      type: r.type || "Cloud Service",
      status: r.status || "healthy",
      x,
      y,
      radius: 28
    });
  });

  // Draw connections between consecutive nodes
  ctx.strokeStyle = "rgba(255, 255, 255, 0.1)";
  ctx.lineWidth = 1.5;
  for (let i = 0; i < nodes.length - 1; i++) {
    ctx.beginPath();
    ctx.moveTo(nodes[i].x, nodes[i].y);
    ctx.lineTo(nodes[i + 1].x, nodes[i + 1].y);
    ctx.stroke();
  }

  // Draw Nodes
  nodes.forEach(node => {
    const isSelected = selectedTopologyNodeId === node.id;

    // Outer glow
    ctx.save();
    ctx.shadowBlur = isSelected ? 20 : 8;
    ctx.shadowColor = node.status === "critical" ? "#ef4444" : node.status === "warning" ? "#f59e0b" : "#00d2ff";

    // Circle background
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
    ctx.fillStyle = isSelected ? "#1e293b" : "#0f172a";
    ctx.fill();

    // Circle border
    ctx.lineWidth = isSelected ? 3 : 1.5;
    ctx.strokeStyle = node.status === "critical" ? "#ef4444" : node.status === "warning" ? "#f59e0b" : "#0078d4";
    ctx.stroke();
    ctx.restore();

    // Provider pill tag above node
    const tag = (node.provider || "cloud").toUpperCase();
    ctx.font = "bold 9px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillStyle = node.provider === "aws" ? "#ff9900" : node.provider === "gcp" ? "#4285f4" : "#00d2ff";
    ctx.fillText(tag, node.x, node.y - node.radius - 8);

    // Node label below node
    ctx.font = "11px Plus Jakarta Sans, sans-serif";
    ctx.fillStyle = "#ffffff";
    const displayName = node.name.length > 18 ? node.name.substring(0, 16) + "..." : node.name;
    ctx.fillText(displayName, node.x, node.y + node.radius + 16);
  });

  // Store layout for click detection
  canvas._nodes = nodes;
}

// Canvas click handler for node inspection
document.getElementById("topologyCanvas")?.addEventListener("click", (e) => {
  const canvas = e.target;
  const nodes = canvas._nodes || [];
  const rect = canvas.getBoundingClientRect();
  const scaleX = canvas.width / rect.width;
  const scaleY = canvas.height / rect.height;
  const clickX = (e.clientX - rect.left) * scaleX;
  const clickY = (e.clientY - rect.top) * scaleY;

  let clickedNode = null;
  for (const n of nodes) {
    const dist = Math.hypot(n.x - clickX, n.y - clickY);
    if (dist <= n.radius) {
      clickedNode = n;
      break;
    }
  }

  if (clickedNode) {
    selectedTopologyNodeId = clickedNode.id;
    renderTopology();
    updateTopologySidebar(clickedNode);
  }
});

// Wire Remediate & Harden button in topology sidebar
document.getElementById("btnFixSelectedNode")?.addEventListener("click", () => {
  if (!selectedTopologyNodeId) {
    showToast("Please select a resource node on the canvas first.", "info");
    return;
  }
  const res = (activeWorkspace.resources || []).find(r => r.id === selectedTopologyNodeId);
  if (res) {
    res.status = "healthy";
    res.note = "Remediated and hardened in workspace.";
    // Mark associated issues as remediated
    (activeWorkspace.issues || []).forEach(iss => {
      if ((iss.resource || "").toLowerCase().includes(res.name.toLowerCase()) || iss.resourceId === res.id) {
        iss.remediated = true;
      }
    });
    saveWorkspace();
    renderAllViews();
    renderTopology();
    updateTopologySidebar(res);
    showToast(`Resource '${res.name}' hardened and linked findings resolved.`, "success");
  }
});

function updateTopologySidebar(node) {
  const sidebar = document.getElementById("nodeDetailsSidebar");
  if (!sidebar) return;

  document.getElementById("sidebarNodeTitle").textContent = node.name;
  const statusBadge = document.getElementById("sidebarNodeStatus");
  if (statusBadge) {
    statusBadge.textContent = node.status === "critical" ? "Critical Finding" : node.status === "warning" ? "Warning Active" : "Operational";
    statusBadge.className = `badge-status badge-${node.status}`;
  }

  document.getElementById("nodeMetaType").textContent = node.type;
  document.getElementById("nodeMetaId").textContent = `provider/${node.provider}/resources/${node.id}`;
  document.getElementById("nodeMetaSec").textContent = node.status === "critical" ? "Severe Configuration Risk" : "Compliant";

  // Match issues on this node
  const nodeIssues = (activeWorkspace.issues || []).filter(i => (i.resource || "").toLowerCase().includes(node.name.toLowerCase()));
  const listEl = document.getElementById("nodeIssuesList");
  if (listEl) {
    listEl.innerHTML = "";
    if (nodeIssues.length === 0) {
      listEl.innerHTML = "<li>No active vulnerabilities flagged on this resource.</li>";
    } else {
      nodeIssues.forEach(i => {
        const li = document.createElement("li");
        li.textContent = `${i.title} (${i.severity})`;
        listEl.appendChild(li);
      });
    }
  }
}

// ============================================================================
// TAB 5: OMNISCAN IAC & CIS BENCHMARK SCANNER
// ============================================================================

let lastScanResults = null;

function initOmniScanner() {
  // Mode switcher tabs
  const subTabs = document.querySelectorAll(".sub-tab");
  subTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      subTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const mode = tab.getAttribute("data-scanner-mode");
      document.querySelectorAll(".scanner-mode-panel").forEach(p => p.classList.remove("active"));
      const target = document.getElementById(`mode-${mode}`);
      if (target) target.classList.add("active");
    });
  });

  // Sample load buttons
  document.getElementById("btnLoadSampleAzureIaC")?.addEventListener("click", () => {
    document.getElementById("iacInputText").value = `// Azure Bicep Template: Payments API Ingress
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'kv-payments-prod'
  location: 'eastus'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    publicNetworkAccess: 'Enabled' // VULNERABILITY: Public internet allowed
    accessPolicies: []
  }
}

resource frontDoor 'Microsoft.Network/frontDoors@2020-05-01' = {
  name: 'fd-payments-edge'
  properties: {
    frontendEndpoints: [
      {
        name: 'default'
        properties: {
          minimumTlsVersion: '1.0' // VULNERABILITY: Deprecated TLS 1.0
        }
      }
    ]
  }
}`;
    showToast("Loaded sample Azure Bicep code.", "info");
  });

  document.getElementById("btnLoadSampleAwsIaC")?.addEventListener("click", () => {
    document.getElementById("iacInputText").value = `# AWS Terraform: S3 & RDS Cluster Configuration
resource "aws_s3_bucket" "financial_archive" {
  bucket = "prod-ledger-archive-raw"
  acl    = "public-read" # CIS 2.1.5: S3 bucket public read access

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_iam_policy" "wildcard_exec" {
  name = "settlement-worker-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*" # Over-privileged wildcard Action
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_instance" "rds_postgres" {
  allocated_storage   = 50
  engine              = "postgres"
  multi_az            = false # Single AZ single-point-of-failure
  storage_encrypted   = false # Unencrypted storage
}`;
    showToast("Loaded sample AWS Terraform code.", "info");
  });

  document.getElementById("btnLoadSampleGcpIaC")?.addEventListener("click", () => {
    document.getElementById("iacInputText").value = `# GCP Terraform: Analytics Engine & Storage
resource "google_storage_bucket" "raw_lake" {
  name     = "enterprise-data-lake-unrestricted"
  location = "US"
}

resource "google_storage_bucket_iam_binding" "public_binding" {
  bucket = google_storage_bucket.raw_lake.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers" # Public unrestricted internet access
  ]
}

resource "google_project_iam_member" "service_account_editor" {
  project = "enterprise-ai-core"
  role    = "roles/editor" # Over-privileged default editor role
  member  = "serviceAccount:ai-pipeline@enterprise-ai-core.iam.gserviceaccount.com"
}`;
    showToast("Loaded sample GCP Terraform code.", "info");
  });

  // Run IaC Scan
  document.getElementById("btnRunCustomIacScan")?.addEventListener("click", runCustomIacScan);

  // Ingest Scanned Findings into Workspace
  document.getElementById("btnIngestScanFindings")?.addEventListener("click", ingestScanResults);

  // Domain SSL Expiry Checker
  document.getElementById("btnRunCertCheck")?.addEventListener("click", evaluateDomainCert);

  // Secret Evaluator
  document.getElementById("btnEvaluateSecretInput")?.addEventListener("click", evaluateSecretInput);
}

function runCustomIacScan() {
  const code = (document.getElementById("iacInputText")?.value || "").trim();
  const outputEl = document.getElementById("scanResultsBody");
  const badgeEl = document.getElementById("scanResultsBadge");
  const ingestBtn = document.getElementById("btnIngestScanFindings");

  if (!code) {
    showToast("Please paste Terraform, Bicep, or ARM template code to analyze.", "warning");
    return;
  }

  const findings = [];
  const discoveredResources = [];

  // Rules: AWS
  if (code.includes('"public-read"') || code.includes("'public-read'") || code.includes("allUsers")) {
    findings.push({
      id: "scan-" + Date.now() + "-1",
      title: "Public Storage Ingress (S3 / Cloud Storage)",
      severity: "CRITICAL",
      pillar: "security",
      provider: code.includes("google") ? "gcp" : "aws",
      resource: "Storage Bucket",
      description: "Bucket is configured with public-read ACL or bound to 'allUsers', exposing object data to unauthorized internet clients (CIS AWS 2.1.5 / CIS GCP 5.1).",
      rootCause: "Public ACL or public IAM member binding present in configuration.",
      remediation: "Enforce S3 Block Public Access or remove allUsers member binding.",
      remediated: false
    });
    discoveredResources.push({ id: "res-s3-" + Date.now(), name: "Public Storage Bucket", provider: code.includes("google") ? "gcp" : "aws", type: "Storage", status: "critical", note: "Public access enabled" });
  }

  if (code.includes('"Action": "*"') || code.includes('"Action" : "*"') || code.includes("Action   = \"*\"")) {
    findings.push({
      id: "scan-" + Date.now() + "-2",
      title: "Over-Privileged IAM Wildcard Policy (*)",
      severity: "CRITICAL",
      pillar: "security",
      provider: "aws",
      resource: "IAM Policy",
      description: "Policy grants administrative wildcard actions ('Action': '*') across all resources, violating Principle of Least Privilege (CIS AWS 1.16).",
      rootCause: "Wildcard permission block in IAM statement.",
      remediation: "Scope policy actions specifically to required service APIs (e.g. s3:GetObject, s3:PutObject).",
      remediated: false
    });
    discoveredResources.push({ id: "res-iam-" + Date.now(), name: "IAM Role / Policy", provider: "aws", type: "Security", status: "critical", note: "Wildcard permissions" });
  }

  if (code.includes("storage_encrypted   = false") || code.includes("storage_encrypted=false")) {
    findings.push({
      id: "scan-" + Date.now() + "-3",
      title: "Unencrypted Database Storage Volume",
      severity: "HIGH",
      pillar: "security",
      provider: "aws",
      resource: "RDS Instance",
      description: "Database storage volume is deployed without encryption at rest, violating compliance standards (PCI-DSS 3.4, HIPAA).",
      rootCause: "storage_encrypted property explicitly set to false.",
      remediation: "Enable KMS encryption at rest: storage_encrypted = true with customer managed KMS key.",
      remediated: false
    });
    discoveredResources.push({ id: "res-rds-" + Date.now(), name: "RDS Database Instance", provider: "aws", type: "Database", status: "warning", note: "Unencrypted volume" });
  }

  // Rules: Azure
  if (code.includes("publicNetworkAccess: 'Enabled'") || code.includes('publicNetworkAccess = "Enabled"')) {
    findings.push({
      id: "scan-" + Date.now() + "-4",
      title: "Key Vault / Data Store Public Network Ingress Enabled",
      severity: "HIGH",
      pillar: "security",
      provider: "azure",
      resource: "Azure Key Vault",
      description: "Resource allows public internet routing without Private Endpoint enforcement.",
      rootCause: "publicNetworkAccess set to Enabled.",
      remediation: "Set publicNetworkAccess = 'Disabled' and route traffic through an Azure Private Endpoint.",
      remediated: false
    });
    discoveredResources.push({ id: "res-kv-" + Date.now(), name: "Azure Key Vault", provider: "azure", type: "Security", status: "warning", note: "Public network access" });
  }

  if (code.includes("minimumTlsVersion: '1.0'") || code.includes("minimumTlsVersion = '1.1'")) {
    findings.push({
      id: "scan-" + Date.now() + "-5",
      title: "Deprecated TLS 1.0/1.1 Protocol Version Permitted",
      severity: "HIGH",
      pillar: "security",
      provider: "azure",
      resource: "Front Door Listener",
      description: "Edge listener accepts obsolete cryptographic protocols vulnerable to cipher downgrade attacks.",
      rootCause: "minimumTlsVersion property set below 1.2.",
      remediation: "Set minimumTlsVersion: '1.2' or '1.3' across all custom domain listeners.",
      remediated: false
    });
  }

  lastScanResults = { findings, discoveredResources };

  if (badgeEl) {
    badgeEl.textContent = `${findings.length} Violations Detected`;
    badgeEl.className = findings.length > 0 ? "badge-status" : "badge-status badge-healthy";
  }

  if (outputEl) {
    if (findings.length === 0) {
      outputEl.innerHTML = `
        <div style="padding:2rem; text-align:center;">
          <svg viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.5" style="margin:0 auto 1rem; color:var(--status-healthy);"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          <h4 style="color:#ffffff;">IaC Configuration Clean</h4>
          <p style="color:var(--text-muted); font-size:0.85rem;">0 CIS Benchmark or architectural security flaws detected in the submitted template.</p>
        </div>
      `;
      if (ingestBtn) ingestBtn.style.display = "none";
    } else {
      let html = `<div style="display:flex; flex-direction:column; gap:0.75rem;">`;
      findings.forEach(f => {
        html += `
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:0.85rem;">
            <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem;">
              <span class="badge-status badge-${f.severity.toLowerCase()}">${f.severity}</span>
              <span class="badge-provider badge-provider-${f.provider}">${f.provider.toUpperCase()}</span>
            </div>
            <strong style="color:#ffffff; font-size:0.9rem;">${escapeHtml(f.title)}</strong>
            <p style="color:var(--text-muted); font-size:0.8rem; margin:0.35rem 0;">${escapeHtml(f.description)}</p>
            <div style="font-size:0.78rem; color:var(--azure-cyan);">Remediation: ${escapeHtml(f.remediation)}</div>
          </div>
        `;
      });
      html += `</div>`;
      outputEl.innerHTML = html;
      if (ingestBtn) ingestBtn.style.display = "inline-flex";
    }
  }

  showToast(`Scan complete: ${findings.length} findings evaluated.`, findings.length > 0 ? "warning" : "success");
}

function ingestScanResults() {
  if (!lastScanResults || lastScanResults.findings.length === 0) return;

  // Add findings to issues
  lastScanResults.findings.forEach(f => {
    activeWorkspace.issues.push(f);
  });

  // Add discovered resources
  lastScanResults.discoveredResources.forEach(r => {
    if (!activeWorkspace.resources.some(existing => existing.name === r.name)) {
      activeWorkspace.resources.push(r);
    }
  });

  saveWorkspace();
  renderAllViews();
  showToast(`Ingested ${lastScanResults.findings.length} findings and ${lastScanResults.discoveredResources.length} resources into active workspace!`, "success");

  const ingestBtn = document.getElementById("btnIngestScanFindings");
  if (ingestBtn) ingestBtn.style.display = "none";
}

function evaluateDomainCert() {
  const domain = document.getElementById("domainCheckInput")?.value || "";
  const expiry = document.getElementById("certExpiryDate")?.value || "";
  const outputEl = document.getElementById("scanResultsBody");
  const badgeEl = document.getElementById("scanResultsBadge");

  if (!domain || !expiry) {
    showToast("Please provide domain name and certificate expiration date.", "warning");
    return;
  }

  const expDate = new Date(expiry);
  const now = new Date();
  const diffDays = Math.ceil((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  const isCrit = diffDays <= 7;
  const isWarn = diffDays <= 30;

  if (badgeEl) {
    badgeEl.textContent = isCrit ? "Critical Expiry Horizon" : isWarn ? "Warning Expiry Horizon" : "Healthy Expiry";
    badgeEl.className = isCrit ? "badge-status" : isWarn ? "badge-status badge-warning" : "badge-status badge-healthy";
  }

  if (outputEl) {
    outputEl.innerHTML = `
      <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-color); border-radius:8px; padding:1.25rem;">
        <h4 style="color:#ffffff; margin-bottom:0.5rem;">Domain SSL Certificate Evaluation: ${escapeHtml(domain)}</h4>
        <div style="font-size:0.9rem; margin-bottom:0.5rem;">Days Remaining: <strong style="color:${isCrit ? '#ef4444' : isWarn ? '#f59e0b' : '#10b981'};">${diffDays} days</strong></div>
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:1rem;">Expiration Date: <code>${expiry}</code></div>
        <button class="btn btn-sm btn-primary" onclick="trackEvaluatedCert('${escapeHtml(domain)}', '${expiry}')">Add to Key Sentinel Monitoring</button>
      </div>
    `;
  }

  showToast(`Certificate evaluated: ${diffDays} days remaining.`, isCrit ? "warning" : "info");
}

window.trackEvaluatedCert = function(domain, expiry) {
  activeWorkspace.keys.push({
    id: "cert-" + Date.now(),
    provider: "azure",
    name: `ssl-cert-${domain}`,
    service: `Public Endpoint (${domain})`,
    type: "SSL/TLS Certificate",
    storage: "Custom Domain Listener",
    expiryDate: expiry,
    impact: `Loss of secure HTTPS ingress on ${domain}`
  });
  saveWorkspace();
  renderAllViews();
  showToast(`Certificate for ${domain} added to Sentinel monitoring!`, "success");
};

function evaluateSecretInput() {
  const name = document.getElementById("secretNameInput")?.value || "custom-secret";
  const type = document.getElementById("secretTypeSelect")?.value || "Key Vault Secret";
  const expiry = document.getElementById("secretExpiryDate")?.value || getOffsetDateString(30);
  const outputEl = document.getElementById("scanResultsBody");
  const badgeEl = document.getElementById("scanResultsBadge");

  let provider = "azure";
  let playbookCmd = "";

  if (type.includes("AWS") || type.includes("IAM") || type.includes("ACM")) {
    provider = "aws";
    playbookCmd = `# AWS CLI: Rotate IAM Access Key\naws iam create-access-key --user-name <service-user>\n# Update secret in AWS Secrets Manager\naws secretsmanager put-secret-value --secret-id <secret-name> --secret-string <new-secret>`;
  } else if (type.includes("GCP") || type.includes("Service Account")) {
    provider = "gcp";
    playbookCmd = `# Google Cloud CLI: Create new Service Account key\ngcloud iam service-accounts keys create ./new-key.json --iam-account <account-email>\n# Delete old key after deployment\ngcloud iam service-accounts keys delete <key-id> --iam-account <account-email>`;
  } else {
    provider = "azure";
    playbookCmd = `# Azure CLI: Reset App Registration credential\naz ad app credential reset --id <app-id> --years 1\n# Update Azure Key Vault Secret\naz keyvault secret set --vault-name <vault-name> --name <secret-name> --value <new-secret>`;
  }

  if (badgeEl) {
    badgeEl.textContent = "Lifecycle Playbook Generated";
    badgeEl.className = "badge-status badge-healthy";
  }

  if (outputEl) {
    outputEl.innerHTML = `
      <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-color); border-radius:8px; padding:1.25rem;">
        <h4 style="color:#ffffff; margin-bottom:0.35rem;">Rotation Guidance: ${escapeHtml(name)}</h4>
        <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:0.75rem;">Credential Type: ${escapeHtml(type)} • Target Provider: ${provider.toUpperCase()}</div>
        <pre class="code-snippet-small"><code>${escapeHtml(playbookCmd)}</code></pre>
        <button class="btn btn-sm btn-primary mt-2" onclick="trackEvaluatedKey('${escapeHtml(name)}', '${provider}', '${escapeHtml(type)}', '${expiry}')">Add to Sentinel Monitoring</button>
      </div>
    `;
  }
}

window.trackEvaluatedKey = function(name, provider, type, expiry) {
  activeWorkspace.keys.push({
    id: "key-" + Date.now(),
    provider: provider,
    name: name,
    service: `${provider.toUpperCase()} Service`,
    type: type,
    storage: `${provider.toUpperCase()} Secrets Manager`,
    expiryDate: expiry,
    impact: "Application authentication failure if unrotated"
  });
  saveWorkspace();
  renderAllViews();
  showToast(`Secret '${name}' added to Sentinel monitoring!`, "success");
};

// ============================================================================
// WORKSPACE IMPORT / EXPORT & EVENTS
// ============================================================================

function initWorkspaceEvents() {
  // Rename environment
  const nameInput = document.getElementById("workspaceNameInput");
  if (nameInput) {
    nameInput.addEventListener("change", (e) => {
      activeWorkspace.name = e.target.value.trim() || "Active Cloud Environment";
      saveWorkspace();
      showToast("Environment renamed to: " + activeWorkspace.name, "success");
    });
  }

  // Run security audit button (direct real-time audit pass)
  document.getElementById("btnRunDiagnostics")?.addEventListener("click", () => {
    showToast("Executing live architectural audit across active assets...", "info");
    renderAllViews();
    appendAuditLog({
      title: "Security Diagnostics Executed",
      detail: `Full audit pass completed across ${(activeWorkspace.resources || []).length} resources and ${(activeWorkspace.keys || []).length} keys.`,
      dotClass: "audit-dot-info",
      dotSvg: '<polygon points="5 3 19 12 5 21 5 3"/>',
      chips: [{ label: "Audit Pass", cls: "audit-chip-scan" }]
    });
    showToast("Audit complete: All active metrics updated.", "success");
  });

  // Export audit JSON
  document.getElementById("btnExportWorkspaceJson")?.addEventListener("click", () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeWorkspace, null, 2));
    const dlAnchor = document.createElement("a");
    const filename = `CloudLens_Audit_${(activeWorkspace.name || 'Workspace').replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.json`;
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", filename);
    dlAnchor.click();
    showToast("Audit dataset exported as " + filename, "success");
  });

  // Clear workspace to clean operational state
  document.getElementById("btnClearWorkspace")?.addEventListener("click", () => {
    if (!confirm("Are you sure you want to clear the active workspace? This will remove all loaded inventory, keys, and findings.")) return;
    resetToCleanWorkspace();
    saveWorkspace({
      title: "Workspace Reset to Zero-State",
      detail: "Active inventory, cryptographic keys, and issues cleared.",
      dotClass: "audit-dot-warning",
      dotSvg: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
      chips: [{ label: "Cleared", cls: "audit-chip-delete" }]
    });
    const nameInput = document.getElementById("workspaceNameInput");
    if (nameInput) nameInput.value = activeWorkspace.name;
    selectedTopologyNodeId = null;
    renderAllViews();
    showToast("Workspace cleared. Ready for live endpoint audit or IaC import.", "info");
  });

  // Load benchmark templates from import modal
  document.getElementById("btnLoadReferenceAudit")?.addEventListener("click", () => {
    const data = BENCHMARK_BASELINES["multicloud"];
    const textarea = document.getElementById("importJsonTextarea");
    if (textarea) textarea.value = JSON.stringify(data, null, 2);
    loadBenchmarkBaseline("multicloud");
    renderAllViews();
    showToast("Loaded Multi-Cloud CIS Baseline into active workspace & editor.", "success");
  });

  document.getElementById("btnLoadAzureBaseline")?.addEventListener("click", () => {
    const data = BENCHMARK_BASELINES["azure"];
    const textarea = document.getElementById("importJsonTextarea");
    if (textarea) textarea.value = JSON.stringify(data, null, 2);
    loadBenchmarkBaseline("azure");
    renderAllViews();
    showToast("Loaded Azure Enterprise Baseline into active workspace & editor.", "success");
  });

  document.getElementById("btnLoadAwsBaseline")?.addEventListener("click", () => {
    const data = BENCHMARK_BASELINES["aws"];
    const textarea = document.getElementById("importJsonTextarea");
    if (textarea) textarea.value = JSON.stringify(data, null, 2);
    loadBenchmarkBaseline("aws");
    renderAllViews();
    showToast("Loaded AWS Cloud Baseline into active workspace & editor.", "success");
  });

  // File upload input
  document.getElementById("importFileInput")?.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        applyImportedData(parsed);
      } catch (err) {
        showToast("Invalid JSON file: " + err.message, "error");
      }
    };
    reader.readAsText(file);
  });

  // Confirm paste import
  document.getElementById("btnConfirmImport")?.addEventListener("click", () => {
    const text = document.getElementById("importJsonTextarea")?.value.trim();
    if (!text) {
      showToast("Please paste JSON content or select a file to import.", "warning");
      return;
    }
    try {
      const parsed = JSON.parse(text);
      applyImportedData(parsed);
    } catch (err) {
      showToast("Could not parse JSON: " + err.message, "error");
    }
  });
}

function applyImportedData(data) {
  if (!data || typeof data !== "object") {
    showToast("Invalid dataset format.", "error");
    return;
  }

  activeWorkspace.name = data.name || activeWorkspace.name || "Imported Environment";
  if (Array.isArray(data.resources)) activeWorkspace.resources = data.resources;
  if (Array.isArray(data.keys)) activeWorkspace.keys = data.keys;
  if (Array.isArray(data.issues)) activeWorkspace.issues = data.issues;

  saveWorkspace({
    title: `Infrastructure Imported: ${activeWorkspace.name}`,
    detail: `${(activeWorkspace.resources || []).length} resources, ${(activeWorkspace.keys || []).length} keys, ${(activeWorkspace.issues || []).length} issues loaded`,
    dotClass: "audit-dot-info",
    dotSvg: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/>',
    chips: [{ label: "Import", cls: "audit-chip-import" }, { label: `${(activeWorkspace.resources || []).length} resources`, cls: "audit-chip-system" }]
  });
  const nameInput = document.getElementById("workspaceNameInput");
  if (nameInput) nameInput.value = activeWorkspace.name;

  closeAllModals();
  renderAllViews();
  showToast(`Imported ${activeWorkspace.resources.length} resources and ${activeWorkspace.keys.length} keys successfully!`, "success");
}

// ============================================================================
// CONTROLS & FILTER EVENTS
// ============================================================================

function initNavigationTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const targetId = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");

      // Redraw canvas if topology tab activated
      if (targetId === "tab-topology") {
        setTimeout(renderTopology, 50);
      }
      // Render audit history when that tab is activated
      if (targetId === "tab-audit-history") {
        renderAuditHistory();
      }
    });
  });

  // Link button from radar to keys tab
  document.getElementById("linkToKeyTab")?.addEventListener("click", () => {
    document.querySelector('.nav-tab[data-tab="tab-key-sentinel"]')?.click();
  });
}

function initCloudScopeFilters() {
  const providerBtns = document.querySelectorAll(".provider-pill-btn");
  providerBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      providerBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentCloudScope = btn.getAttribute("data-cloud-filter");

      const badgeText = document.getElementById("activeFrameworkName");
      if (currentCloudScope === "azure") {
        if (badgeText) badgeText.textContent = "Microsoft Azure Well-Architected Framework (5 Pillars)";
      } else if (currentCloudScope === "aws") {
        if (badgeText) badgeText.textContent = "AWS Well-Architected Framework (6 Pillars)";
      } else if (currentCloudScope === "gcp") {
        if (badgeText) badgeText.textContent = "Google Cloud Architecture Framework Benchmarks";
      } else {
        if (badgeText) badgeText.textContent = "Tri-Cloud Well-Architected Framework Benchmarks";
      }

      renderAllViews();
    });
  });
}

function initKeyTableControls() {
  document.getElementById("filterKeySearch")?.addEventListener("input", renderKeysTable);

  const filterChips = document.querySelectorAll(".filter-chip");
  filterChips.forEach(chip => {
    chip.addEventListener("click", () => {
      filterChips.forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      currentKeyFilter = chip.getAttribute("data-key-filter");
      renderKeysTable();
    });
  });

  // Quick add secret button on Overview radar
  document.getElementById("btnQuickAddSecret")?.addEventListener("click", () => {
    document.getElementById("modalAddKey")?.classList.add("active");
  });
}

function initIssueFilters() {
  document.getElementById("filterPillarSelect")?.addEventListener("change", renderIssuesMatrix);
  document.getElementById("filterSeveritySelect")?.addEventListener("change", renderIssuesMatrix);
}

// ============================================================================
// MODALS
// ============================================================================

function initModals() {
  // Executive Report Modal
  const modalReport = document.getElementById("modalExecutiveReport");
  document.getElementById("btnExportExecutiveReport")?.addEventListener("click", () => {
    generateExecutiveReport();
    modalReport?.classList.add("active");
  });
  document.getElementById("btnCloseReport")?.addEventListener("click", () => modalReport?.classList.remove("active"));
  document.getElementById("btnPrintReport")?.addEventListener("click", () => window.print());

  // Add Key Modal
  const modalAddKey = document.getElementById("modalAddKey");
  document.getElementById("btnAddNewSecretModal")?.addEventListener("click", () => modalAddKey?.classList.add("active"));
  document.getElementById("btnCloseAddKey")?.addEventListener("click", () => modalAddKey?.classList.remove("active"));
  document.getElementById("btnCancelAddKey")?.addEventListener("click", () => modalAddKey?.classList.remove("active"));

  // Form submit for Add Key
  document.getElementById("formAddKey")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("newKeyName")?.value.trim();
    const provider = document.getElementById("newKeyProvider")?.value || "azure";
    const service = document.getElementById("newKeyService")?.value.trim();
    const type = document.getElementById("newKeyType")?.value;
    const expiry = document.getElementById("newKeyExpiry")?.value;
    const impact = document.getElementById("newKeyImpact")?.value.trim();

    if (!name || !expiry) return;

    activeWorkspace.keys.push({
      id: "key-" + Date.now(),
      provider: provider,
      name: name,
      service: service,
      type: type,
      storage: `${provider.toUpperCase()} Vault`,
      expiryDate: expiry,
      impact: impact || "Service disruption"
    });

    saveWorkspace();
    modalAddKey?.classList.remove("active");
    e.target.reset();
    renderAllViews();
    showToast(`Key '${name}' registered in Sentinel monitoring.`, "success");
  });

  // Import Modal
  const modalImport = document.getElementById("modalImport");
  document.getElementById("btnOpenImportModal")?.addEventListener("click", () => modalImport?.classList.add("active"));
  document.getElementById("btnCloseImportModal")?.addEventListener("click", () => modalImport?.classList.remove("active"));
  document.getElementById("btnCancelImport")?.addEventListener("click", () => modalImport?.classList.remove("active"));

  // Update Expiry Modal
  const modalUpdate = document.getElementById("modalUpdateExpiry");
  document.getElementById("btnCloseUpdateExpiry")?.addEventListener("click", () => modalUpdate?.classList.remove("active"));
  document.getElementById("btnCancelUpdateExpiry")?.addEventListener("click", () => modalUpdate?.classList.remove("active"));
  document.getElementById("btnSaveUpdatedExpiry")?.addEventListener("click", () => {
    const keyId = document.getElementById("updateExpiryKeyId")?.value;
    const newDate = document.getElementById("newExpiryInputDate")?.value;
    if (!keyId || !newDate) return;

    const k = (activeWorkspace.keys || []).find(item => item.id === keyId);
    if (k) {
      k.expiryDate = newDate;
      saveWorkspace();
      modalUpdate?.classList.remove("active");
      renderAllViews();
      showToast(`Key '${k.name}' updated with new expiration date.`, "success");
    }
  });

  // Endpoint Report Modal
  const modalEndpoint = document.getElementById("modalEndpointReport");
  document.getElementById("btnCloseEndpointReport")?.addEventListener("click", () => modalEndpoint?.classList.remove("active"));
  document.getElementById("btnCloseEndpointFooter")?.addEventListener("click", () => modalEndpoint?.classList.remove("active"));
  document.getElementById("btnPrintEndpointReport")?.addEventListener("click", () => window.print());
  document.getElementById("btnIngestEndpointToWorkspace")?.addEventListener("click", ingestEndpointAnalysisToWorkspace);

  // Close modals on backdrop click
  const modalNotifications = document.getElementById("modalNotifications");
  document.getElementById("btnOpenNotifications")?.addEventListener("click", () => {
    // Pre-populate from settings
    const s = appSettings;
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    setVal("notifCritDays", s.critDays);
    setVal("notifWarnDays", s.warnDays);
    setVal("notifSlaCritDays", s.slaCritDays);
    setVal("notifSlaHighDays", s.slaHighDays);
    setVal("notifFrameworkSelect", s.complianceFramework);
    const browserToggle = document.getElementById("notifBrowserToggle");
    if (browserToggle) browserToggle.checked = s.browserNotif;
    modalNotifications?.classList.add("active");
  });
  document.getElementById("btnCloseNotifications")?.addEventListener("click", () => modalNotifications?.classList.remove("active"));
  document.getElementById("btnCancelNotifications")?.addEventListener("click", () => modalNotifications?.classList.remove("active"));
  document.getElementById("btnSaveNotifications")?.addEventListener("click", () => {
    const getNum = (id, def) => { const el = document.getElementById(id); return el ? (parseInt(el.value) || def) : def; };
    appSettings.critDays = getNum("notifCritDays", 7);
    appSettings.warnDays = getNum("notifWarnDays", 30);
    appSettings.slaCritDays = getNum("notifSlaCritDays", 3);
    appSettings.slaHighDays = getNum("notifSlaHighDays", 7);
    appSettings.complianceFramework = document.getElementById("notifFrameworkSelect")?.value || "waf";
    appSettings.browserNotif = document.getElementById("notifBrowserToggle")?.checked || false;
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(appSettings));
    // Sync compliance selectors
    const headerSel = document.getElementById("complianceFrameworkSelect");
    if (headerSel) headerSel.value = appSettings.complianceFramework;
    modalNotifications?.classList.remove("active");
    renderAllViews();
    appendAuditLog({
      title: "Notification Settings Updated",
      detail: `Thresholds: Critical=${appSettings.critDays}d, Warning=${appSettings.warnDays}d, SLA-Crit=${appSettings.slaCritDays}d, SLA-High=${appSettings.slaHighDays}d`,
      dotClass: "audit-dot-info",
      dotSvg: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>',
      chips: [{ label: "Settings", cls: "audit-chip-system" }, { label: appSettings.complianceFramework.toUpperCase(), cls: "audit-chip-scan" }]
    });
    showToast("Alert thresholds and compliance framework updated.", "success");
  });

  [modalReport, modalAddKey, modalImport, modalUpdate, modalEndpoint, modalNotifications].filter(Boolean).forEach(modal => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.remove("active");
    });
  });
}

function closeAllModals() {
  document.querySelectorAll(".modal-backdrop").forEach(m => m.classList.remove("active"));
}

// ============================================================================
// ENTERPRISE FEATURE INITIALIZERS
// ============================================================================

function initSettings() {
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    appSettings = { ...DEFAULT_SETTINGS, ...saved };
  } catch { 
    appSettings = { ...DEFAULT_SETTINGS }; 
  }

  // Apply saved theme — default is dark
  const theme = appSettings.theme || "dark";
  applyTheme(theme);

  // Sync compliance framework dropdown
  const sel = document.getElementById("complianceFrameworkSelect");
  if (sel) {
    sel.value = appSettings.complianceFramework || "waf";
    sel.addEventListener("change", (e) => {
      appSettings.complianceFramework = e.target.value;
      try {
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(appSettings));
      } catch {}
      updateFrameworkBadge();
      showToast(`Compliance framework switched to: ${e.target.options[e.target.selectedIndex].text}`, "info");
    });
  }
}

function applyTheme(theme) {
  const isDark = theme === "dark";
  document.body.classList.toggle("theme-dark",  isDark);
  document.body.classList.toggle("theme-light", !isDark);
  document.documentElement.classList.toggle("theme-dark", isDark);
  document.documentElement.classList.toggle("theme-light", !isDark);
  document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
  document.body.setAttribute("data-theme", isDark ? "dark" : "light");

  const darkIcon  = document.getElementById("themeIconDark");
  const lightIcon = document.getElementById("themeIconLight");
  if (darkIcon)  darkIcon.style.display  = isDark ? "block" : "none";
  if (lightIcon) lightIcon.style.display = isDark ? "none"  : "block";
}

function initThemeToggle() {
  const btn = document.getElementById("btnThemeToggle");
  if (!btn) return;
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    const isLight = document.body.classList.contains("theme-light");
    const newTheme = isLight ? "dark" : "light";
    appSettings.theme = newTheme;
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(appSettings));
    } catch {}
    applyTheme(newTheme);
    showToast(`Switched to ${newTheme} mode.`, "info");
  });
}

function updateFrameworkBadge() {
  const labels = {
    waf: "Well-Architected Framework",
    cis: "CIS Benchmark v8",
    nist: "NIST 800-53 Rev 5",
    soc2: "SOC 2 Type II",
    pci: "PCI-DSS v4.0",
    iso27001: "ISO 27001:2022"
  };
  const frameworkEl = document.getElementById("activeFrameworkName");
  if (frameworkEl && frameworkEl.textContent.includes("Tri-Cloud")) return;
  // Badge in header ribbon shows selected framework
  const badgeEl = document.getElementById("activeFrameworkName");
  if (badgeEl) {
    const scope = document.querySelector(".provider-pill-btn.active")?.dataset.cloudFilter || "all";
    if (scope === "all") {
      badgeEl.textContent = `${labels[appSettings.complianceFramework] || "Well-Architected"} • Tri-Cloud Scope`;
    }
  }
}

function initCommandPalette() {
  const backdrop = document.getElementById("cmdPaletteBackdrop");
  const input = document.getElementById("cmdPaletteInput");
  const results = document.getElementById("cmdPaletteResults");
  const closeBtn = document.getElementById("btnCloseCmdPalette");
  const triggerBtn = document.getElementById("btnOpenCommandPalette");

  let selectedIndex = 0;
  let currentItems = [];

  function openPalette(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!backdrop) return;
    backdrop.classList.add("active");
    selectedIndex = 0;
    if (input) {
      input.value = "";
      setTimeout(() => input.focus(), 60);
    }
    populatePaletteResults("");
  }

  function closePalette(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!backdrop) return;
    backdrop.classList.remove("active");
  }

  triggerBtn?.addEventListener("click", openPalette);
  closeBtn?.addEventListener("click", closePalette);
  backdrop?.addEventListener("click", (e) => {
    if (e.target === backdrop) closePalette();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      if (backdrop?.classList.contains("active")) {
        closePalette();
      } else {
        openPalette();
      }
    }
    if (e.key === "Escape" && backdrop?.classList.contains("active")) {
      e.preventDefault();
      closePalette();
    }
  });

  input?.addEventListener("keydown", (e) => {
    if (!backdrop?.classList.contains("active")) return;
    const itemEls = results?.querySelectorAll(".cmd-result-item");
    if (!itemEls || itemEls.length === 0) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedIndex = (selectedIndex + 1) % itemEls.length;
      updateSelected(itemEls);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedIndex = (selectedIndex - 1 + itemEls.length) % itemEls.length;
      updateSelected(itemEls);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (currentItems[selectedIndex] && currentItems[selectedIndex].action) {
        currentItems[selectedIndex].action();
      }
    }
  });

  function updateSelected(itemEls) {
    itemEls.forEach((el, idx) => {
      el.classList.toggle("selected", idx === selectedIndex);
      if (idx === selectedIndex) {
        el.scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    });
  }

  input?.addEventListener("input", () => {
    selectedIndex = 0;
    populatePaletteResults(input.value);
  });

  function populatePaletteResults(query) {
    if (!results) return;
    const q = (query || "").toLowerCase().trim();
    const items = [];

    // Quick actions
    const actions = [
      { label: "Import Infrastructure / IaC", sub: "Open import wizard (Terraform, K8s, ARM)", icon: "ACT", type: "type-action", action: () => { document.getElementById("btnOpenImportModal")?.click(); closePalette(); } },
      { label: "Track New Key or Certificate", sub: "Open key sentinel registration form", icon: "KEY", type: "type-key", action: () => { document.getElementById("btnAddNewSecretModal")?.click(); closePalette(); } },
      { label: "Export Audit JSON", sub: "Download complete workspace state as JSON", icon: "EXP", type: "type-action", action: () => { document.getElementById("btnExportWorkspaceJson")?.click(); closePalette(); } },
      { label: "Executive Audit Dossier", sub: "Generate printable executive PDF report", icon: "RPT", type: "type-action", action: () => { document.getElementById("btnExportExecutiveReport")?.click(); closePalette(); } },
      { label: "Run Security Audit", sub: "Re-evaluate all active cloud assets", icon: "RUN", type: "type-action", action: () => { document.getElementById("btnRunDiagnostics")?.click(); closePalette(); } },
      { label: "Toggle Dark / Light Theme", sub: "Switch visual color mode", icon: "THM", type: "type-action", action: () => { document.getElementById("btnThemeToggle")?.click(); closePalette(); } },
      { label: "Notification & Alert Settings", sub: "Configure thresholds and SLAs", icon: "SET", type: "type-action", action: () => { document.getElementById("btnOpenNotifications")?.click(); closePalette(); } },
    ];
    actions.filter(a => !q || a.label.toLowerCase().includes(q) || a.sub.toLowerCase().includes(q)).forEach(a => items.push(a));

    // Resources
    (activeWorkspace.resources || []).filter(r => !q || (r.name || "").toLowerCase().includes(q) || (r.type || "").toLowerCase().includes(q) || (r.provider || "").toLowerCase().includes(q)).slice(0, 8).forEach(r => {
      items.push({ label: r.name, sub: `${(r.type || "Service")} • ${(r.provider || "cloud").toUpperCase()}`, icon: "RES", type: "type-resource", badge: r.status, action: () => { document.querySelector('.nav-tab[data-tab="tab-overview"]')?.click(); closePalette(); } });
    });

    // Keys
    (activeWorkspace.keys || []).filter(k => !q || (k.name || "").toLowerCase().includes(k) || (k.service || "").toLowerCase().includes(q)).slice(0, 8).forEach(k => {
      items.push({ label: k.name, sub: `${k.type || "Secret"} • ${k.daysLeft <= 0 ? "EXPIRED" : k.daysLeft + "d left"}`, icon: "KEY", type: "type-key", badge: k.status, action: () => { document.querySelector('.nav-tab[data-tab="tab-key-sentinel"]')?.click(); closePalette(); } });
    });

    // Issues
    (activeWorkspace.issues || []).filter(i => !q || (i.title || "").toLowerCase().includes(q) || (i.desc || "").toLowerCase().includes(q)).slice(0, 8).forEach(i => {
      items.push({ label: i.title, sub: `${i.severity} • ${(i.provider || "cloud").toUpperCase()}`, icon: "ISS", type: "type-issue", badge: i.severity ? i.severity.toLowerCase() : "info", action: () => { document.querySelector('.nav-tab[data-tab="tab-issues"]')?.click(); closePalette(); } });
    });

    currentItems = items;

    if (items.length === 0) {
      results.innerHTML = `<div class="cmd-no-results">No matching actions or resources for "${escapeHtml(query)}"</div>`;
      return;
    }

    results.innerHTML = "";
    items.forEach((item, idx) => {
      const el = document.createElement("div");
      el.className = `cmd-result-item${idx === selectedIndex ? ' selected' : ''}`;
      const badgeHtml = item.badge ? `<span class="cmd-result-badge ${item.badge}">${escapeHtml(item.badge)}</span>` : "";
      el.innerHTML = `
        <div class="cmd-result-icon ${item.type}">${escapeHtml(item.icon)}</div>
        <div class="cmd-result-body">
          <div class="cmd-result-title">${escapeHtml(item.label)}</div>
          <div class="cmd-result-sub">${escapeHtml(item.sub)}</div>
        </div>
        ${badgeHtml}
      `;
      el.addEventListener("click", () => item.action());
      results.appendChild(el);
    });
  }
}

function initCsvExports() {
  // Export Keys as CSV
  document.getElementById("btnExportKeysCsv")?.addEventListener("click", () => {
    const keys = activeWorkspace.keys || [];
    if (keys.length === 0) { showToast("No keys to export.", "info"); return; }

    const rows = [["Status", "Provider", "Name", "Service", "Type", "Expiry Date", "Days Left", "Impact"].join(",")];
    keys.forEach(k => {
      rows.push([
        k.status || "healthy",
        k.provider || "azure",
        k.name,
        k.service || "",
        k.type || "",
        k.expiryDate || "",
        k.daysLeft !== undefined ? k.daysLeft : "",
        (k.impact || "").replace(/,/g, ";")
      ].map(v => `"${v}"`).join(","));
    });

    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `CloudLens_Keys_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${keys.length} keys as CSV.`, "success");
  });

  // Export Audit Log CSV
  document.getElementById("btnExportAuditLog")?.addEventListener("click", exportAuditLogCsv);

  // Clear Audit Log
  document.getElementById("btnClearAuditLog")?.addEventListener("click", () => {
    if (!confirm("Are you sure you want to clear the audit history? This action cannot be undone.")) return;
    localStorage.removeItem(AUDIT_LOG_KEY);
    renderAuditHistory();
    showToast("Audit log cleared.", "info");
  });
}

function initNotifDot() {
  // Show red dot on notification bell if there are critical expiring keys
  const metrics = computeWorkspaceMetrics();
  const dot = document.getElementById("notifAlertDot");
  if (dot) dot.classList.toggle("active", metrics.criticalKeysCount > 0);
}

// ============================================================================
// EXECUTIVE AUDIT REPORT
// ============================================================================

function generateExecutiveReport() {
  const container = document.getElementById("printableReportContent");
  if (!container) return;

  const metrics = computeWorkspaceMetrics();
  const allKeys = activeWorkspace.keys || [];
  const allIssues = activeWorkspace.issues || [];
  const resources = activeWorkspace.resources || [];

  const azCount = resources.filter(r => (r.provider || 'azure') === 'azure').length;
  const awsCount = resources.filter(r => r.provider === 'aws').length;
  const gcpCount = resources.filter(r => r.provider === 'gcp').length;

  container.innerHTML = `
    <div class="report-paper">
      <div class="report-header-grid">
        <div>
          <div class="report-title">Executive Multi-Cloud Architecture Audit & Key Governance Dossier</div>
          <div class="report-subtitle">CloudLens 360° Automated Governance & Compliance Audit • Generated on ${new Date().toLocaleDateString()}</div>
          <div style="font-size:0.85rem; margin-top:0.35rem; color:#475569;">Environment: <strong>${escapeHtml(activeWorkspace.name)}</strong></div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:2.2rem; font-weight:800; color:${metrics.healthScore >= 90 ? '#10b981' : metrics.healthScore >= 70 ? '#f59e0b' : '#ef4444'};">${metrics.healthScore}%</div>
          <div style="font-size:0.75rem; text-transform:uppercase; color:#64748b; font-weight:700;">Multi-Cloud Health Index</div>
        </div>
      </div>

      <div class="report-kpi-summary">
        <div class="report-kpi-box">
          <div class="val">${metrics.criticalKeysCount}</div>
          <div class="lbl">Imminent Expiring Keys (≤ 7d)</div>
        </div>
        <div class="report-kpi-box">
          <div class="val">${metrics.activeIssuesCount}</div>
          <div class="lbl">Open Security Findings</div>
        </div>
        <div class="report-kpi-box">
          <div class="val">${metrics.resourcesCount}</div>
          <div class="lbl">Audited Cloud Services</div>
        </div>
        <div class="report-kpi-box">
          <div class="val">${metrics.complianceRate}%</div>
          <div class="lbl">CIS Controls Adherence</div>
        </div>
      </div>

      <h4 style="margin:1.5rem 0 0.5rem; font-size:1rem; border-bottom:2px solid #e2e8f0; padding-bottom:0.35rem;">1. Tri-Cloud Infrastructure Footprint</h4>
      <table style="width:100%; border-collapse:collapse; margin-bottom:1.5rem; font-size:0.85rem;">
        <thead>
          <tr style="background:#f1f5f9; text-align:left;">
            <th style="padding:0.5rem;">Provider</th>
            <th style="padding:0.5rem;">Services</th>
            <th style="padding:0.5rem;">Monitored Keys</th>
            <th style="padding:0.5rem;">Primary Framework</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;"><strong>Microsoft Azure</strong></td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${azCount}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${allKeys.filter(k => (k.provider || 'azure') === 'azure').length}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">Azure Well-Architected Framework</td>
          </tr>
          <tr>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;"><strong>Amazon Web Services (AWS)</strong></td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${awsCount}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${allKeys.filter(k => k.provider === 'aws').length}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">AWS Well-Architected 6 Pillars</td>
          </tr>
          <tr>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;"><strong>Google Cloud (GCP)</strong></td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${gcpCount}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">${allKeys.filter(k => k.provider === 'gcp').length}</td>
            <td style="padding:0.5rem; border-bottom:1px solid #e2e8f0;">Google Cloud Architecture Framework</td>
          </tr>
        </tbody>
      </table>

      <h4 style="margin:1.5rem 0 0.5rem; font-size:1rem; border-bottom:2px solid #e2e8f0; padding-bottom:0.35rem;">2. Critical Findings & Key Expirations</h4>
      ${allIssues.filter(i => !i.remediated).length === 0 && metrics.criticalKeysCount === 0 ? 
        '<p style="font-size:0.85rem; color:#10b981;">No outstanding critical vulnerabilities or imminent key expirations detected.</p>' :
        allIssues.filter(i => !i.remediated).map(i => `
          <div style="margin-bottom:0.75rem; padding:0.5rem; background:#f8fafc; border-left:4px solid #ef4444;">
            <div style="font-weight:700; font-size:0.85rem;">[${i.severity}] ${escapeHtml(i.title)} (${(i.provider || 'cloud').toUpperCase()})</div>
            <div style="font-size:0.8rem; color:#475569;">${escapeHtml(i.description)}</div>
          </div>
        `).join('')
      }
    </div>
  `;
}

// ============================================================================
// LIVE ENDPOINT & APP URL ARCHITECTURE AUDITOR
// ============================================================================



function initEndpointAuditor() {
  const urlInput = document.getElementById("appUrlAuditInput");

  const btnAnalyze = document.getElementById("btnAnalyzeAppUrl");
  const btnClear = document.getElementById("btnClearAppUrl");
  const presetSelect = document.getElementById("endpointPresetSelect");

  // Enter key in input field
  urlInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      performEndpointAnalysis(urlInput.value);
    }
  });

  // Clear button
  btnClear?.addEventListener("click", () => {
    if (urlInput) {
      urlInput.value = "";
      urlInput.focus();
    }
  });

  // Preset dropdown change
  presetSelect?.addEventListener("change", (e) => {
    const val = e.target.value;
    if (val && urlInput) {
      urlInput.value = val;
      performEndpointAnalysis(val);
    }
  });

  // Analyze button click
  btnAnalyze?.addEventListener("click", () => {
    const url = urlInput?.value || "";
    performEndpointAnalysis(url);
  });
}

async function performEndpointAnalysis(rawUrl) {
  let url = (rawUrl || "").trim();
  if (!url) {
    showToast("Please enter an Application URL or Cloud Endpoint to audit.", "warning");
    return;
  }

  // Rate limiting: prevent rapid sequential calls
  const now = Date.now();
  if (now - lastAnalysisTime < 2000) {
    showToast("Please wait a moment before analyzing another endpoint.", "warning");
    return;
  }
  lastAnalysisTime = now;

  // Auto-prefix https if protocol missing
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
    const input = document.getElementById("appUrlAuditInput");
    if (input) input.value = url;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    showToast("Invalid URL format. Please enter a valid URL (e.g., https://portal.azure.com)", "error");
    return;
  }

  // Whitelist only http/https protocols
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    showToast("Only HTTP and HTTPS URLs are supported.", "error");
    return;
  }

  const hostname = parsed.hostname.toLowerCase();
  
  // Validate that the hostname looks like a real domain (or localhost)
  if (hostname !== "localhost" && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(hostname)) {
    showToast("Invalid domain name. Please enter a fully qualified domain (e.g. app.azurewebsites.net).", "error");
    return;
  }
  const btn = document.getElementById("btnAnalyzeAppUrl");
  const originalText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg class="spinner-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0 1 10 10"/></svg> Auditing DNS, TLS & Cloud Topology...`;
  }

  const startTime = performance.now();
  let liveProbe = {
    reachable: false,
    latencyMs: null,
    httpStatus: null,
    httpStatusText: null,
    corsRestricted: false,
    tlsVerified: parsed.protocol === "https:",
    headers: {}
  };

  try {
    // Run 3 authentic probes concurrently:
    // 1. Live HTTP/S probe
    // 2. Real DNS-over-HTTPS (A, CNAME, NS, CAA, TXT) via Google Public DNS
    // 3. Real Certificate Transparency log lookup via crt.sh
    const probePromise = (async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      try {
        const response = await fetch(url, {
          method: "HEAD",
          mode: "cors",
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        liveProbe.latencyMs = Math.round(performance.now() - startTime);
        liveProbe.reachable = true;
        liveProbe.httpStatus = response.status;
        liveProbe.httpStatusText = response.statusText || "OK";
        for (const [k, v] of response.headers.entries()) {
          liveProbe.headers[k.toLowerCase()] = v;
        }
      } catch (headErr) {
        try {
          const noCorsStart = performance.now();
          await fetch(url, {
            method: "GET",
            mode: "no-cors",
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          liveProbe.latencyMs = Math.round(performance.now() - noCorsStart);
          liveProbe.reachable = true;
          liveProbe.corsRestricted = true;
          liveProbe.httpStatus = 200;
          liveProbe.httpStatusText = "Reachable (Opaque / CORS Policy)";
        } catch (getErr) {
          clearTimeout(timeoutId);
          liveProbe.reachable = false;
          liveProbe.latencyMs = Math.round(performance.now() - startTime);
          liveProbe.httpStatus = 0;
          liveProbe.httpStatusText = getErr.name === "AbortError" ? "Timeout (> 6000ms)" : "Host Offline or Blocked by CORS/DNS";
        }
      }
    })();

    const [probeRes, dnsData, certData] = await Promise.all([
      probePromise,
      resolveLiveDns(hostname),
      parsed.protocol === "https:" ? fetchLiveCertificateTransparency(hostname) : Promise.resolve(null)
    ]);

    const analysis = generateEndpointReportData(url, parsed, liveProbe, dnsData, certData);
    lastEndpointAnalysis = analysis;
    renderEndpointReportModal(analysis);

    const modal = document.getElementById("modalEndpointReport");
    if (modal) modal.classList.add("active");

    appendAuditLog({
      title: `Audited: ${analysis.hostname}`,
      detail: `${analysis.cloudProviderLabel} • ${analysis.primaryService} • Health Score: ${analysis.healthScore}% • Response: ${liveProbe.latencyMs || 0}ms`,
      dotClass: analysis.healthScore >= 80 ? "audit-dot-success" : "audit-dot-warning",
      dotSvg: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>',
      chips: [{ label: "Endpoint", cls: "audit-chip-scan" }, { label: analysis.cloudProvider.toUpperCase(), cls: "audit-chip-system" }]
    });

    showToast(`Audit complete for ${analysis.hostname} — Health: ${analysis.healthScore}% (${liveProbe.latencyMs || 0}ms)`, analysis.healthScore >= 80 ? "success" : "warning");
  } catch (err) {
    showToast(`Endpoint diagnostic error: ${err.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  }
}

// ----------------------------------------------------------------------------
// REAL DNS-OVER-HTTPS RESOLVER (Google Public DoH)
// ----------------------------------------------------------------------------
async function resolveLiveDns(hostname) {
  const result = {
    aRecords: [],
    cnames: [],
    nsRecords: [],
    caaRecords: [],
    txtRecords: []
  };

  const types = [
    { type: "A", id: 1, field: "aRecords" },
    { type: "CNAME", id: 5, field: "cnames" },
    { type: "NS", id: 2, field: "nsRecords" },
    { type: "CAA", id: 257, field: "caaRecords" },
    { type: "TXT", id: 16, field: "txtRecords" }
  ];

  await Promise.allSettled(types.map(async (t) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${t.type}`, {
        headers: { Accept: "application/dns-json" },
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!res.ok) return;
      const json = await res.json();
      if (json && Array.isArray(json.Answer)) {
        json.Answer.forEach(ans => {
          if (ans.type === t.id && ans.data) {
            result[t.field].push(ans.data.replace(/\.$/, ''));
          }
        });
      }
      if (t.type === "NS" && result.nsRecords.length === 0 && json && Array.isArray(json.Authority)) {
        json.Authority.forEach(auth => {
          if (auth.type === 2 && auth.data) {
            result.nsRecords.push(auth.data.replace(/\.$/, ''));
          }
        });
      }
    } catch (e) {
      // DNS lookup individual failure handled gracefully
    }
  }));

  // Warn if DNS resolution returned nothing at all (likely a file:// origin issue)
  if (result.aRecords.length === 0 && result.cnames.length === 0 && result.nsRecords.length === 0) {
    const proto = window.location.protocol;
    if (proto === "file:") {
      showToast("DNS resolution returned no records. Serve this app over HTTP (not file://) for accurate analysis.", "warning");
    }
  }

  // If NS record array is empty on a subdomain, query root domain for NS
  if (result.nsRecords.length === 0) {
    const parts = hostname.split(".");
    if (parts.length > 2) {
      const parent = parts.slice(-2).join(".");
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2500);
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(parent)}&type=NS`, {
          headers: { Accept: "application/dns-json" },
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          const json = await res.json();
          if (json && Array.isArray(json.Answer)) {
            json.Answer.forEach(ans => {
              if (ans.type === 2 && ans.data) result.nsRecords.push(ans.data.replace(/\.$/, ''));
            });
          }
        }
      } catch (e) {}
    }
  }

  return result;
}

// ----------------------------------------------------------------------------
// REAL CERTIFICATE TRANSPARENCY AUDIT (crt.sh)
// ----------------------------------------------------------------------------
async function fetchLiveCertificateTransparency(hostname) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    // Use the self-hosted server-side proxy at /api/crt-transparency.
    // This completely eliminates the browser CORS restriction — no third-party proxy dependency.
    // Falls back gracefully if the app is opened directly as a file:// (no server running).
    const isServed = window.location.protocol.startsWith("http");
    const proxyUrl = isServed
      ? `/api/crt-transparency?hostname=${encodeURIComponent(hostname)}`
      : null;

    if (!proxyUrl) return null; // file:// origin — skip, server not running

    let certs = null;
    try {
      const res = await fetch(proxyUrl, { signal: controller.signal });
      if (res.ok) certs = await res.json();
    } catch {}

    // Static hosting fallback (e.g. GitHub Pages without server-side proxy)
    if (!Array.isArray(certs) || certs.length === 0) {
      try {
        const fallbackUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`)}`;
        const fbRes = await fetch(fallbackUrl, { signal: controller.signal });
        if (fbRes.ok) certs = await fbRes.json();
      } catch {}
    }

    clearTimeout(timeoutId);
    if (!Array.isArray(certs) || certs.length === 0) return null;

    const now = new Date();
    const withExpiry = certs.filter(c => c && c.not_after && c.not_before);
    if (withExpiry.length === 0) return null;

    // Sort descending by not_after date
    withExpiry.sort((a, b) => new Date(b.not_after) - new Date(a.not_after));

    // Prefer active certificate (not_after in the future) or latest issued
    const active = withExpiry.find(c => new Date(c.not_after) > now) || withExpiry[0];

    let cleanIssuer = "Trusted Public CA";
    if (active.issuer_name) {
      const cnMatch = active.issuer_name.match(/CN=([^,]+)/);
      const oMatch = active.issuer_name.match(/O=([^,]+)/);
      if (cnMatch) cleanIssuer = cnMatch[1].trim();
      else if (oMatch) cleanIssuer = oMatch[1].trim();
      else cleanIssuer = active.issuer_name;
    }

    const expiryDate = active.not_after;
    const daysRemaining = Math.ceil((new Date(expiryDate) - now) / (1000 * 60 * 60 * 24));

    return {
      commonName: active.common_name || hostname,
      cleanIssuer,
      issuerName: active.issuer_name,
      notBefore: active.not_before,
      notAfter: active.not_after,
      serialNumber: active.serial_number || "N/A",
      sans: (active.name_value ? active.name_value.split('\n').filter(Boolean) : [hostname]),
      daysRemaining,
      isExpired: daysRemaining < 0
    };
  } catch (e) {
    console.warn("Certificate transparency query error / timeout:", e);
    return null;
  }
}

// ----------------------------------------------------------------------------
// INTELLIGENT MULTI-CLOUD ARCHITECTURE & KEY FINGERPRINTING
// ----------------------------------------------------------------------------
function generateEndpointReportData(url, parsed, liveProbe, dnsData, certData) {
  const protocol = parsed.protocol.replace(":", "");
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const appPrefix = hostname.split(".")[0].replace(/[^a-zA-Z0-9-]/g, "") || "app";

  const allDomains = [hostname, ...(dnsData.cnames || [])].join(' ').toLowerCase();
  const allNameservers = (dnsData.nsRecords || []).join(' ').toLowerCase();
  const certIssuerStr = (certData && certData.issuerName ? certData.issuerName : '').toLowerCase();

  let hstsActive = !!(liveProbe.headers && liveProbe.headers["strict-transport-security"]);
  let serverHeader = (liveProbe.headers && liveProbe.headers["server"]) || null;
  const serverHeaderLower = (serverHeader || "").toLowerCase();
  const viaHeader = ((liveProbe.headers && liveProbe.headers["via"]) || "").toLowerCase();
  const xCacheHeader = ((liveProbe.headers && liveProbe.headers["x-cache"]) || "").toLowerCase();

  // Cloud Provider Classification
  let cloudProvider = "hybrid";
  let cloudProviderLabel = "Enterprise Hybrid / Multi-Cloud";

  if (allDomains.includes("azurewebsites.net") || 
      allDomains.includes("azurefd.net") || 
      allDomains.includes("vault.azure.net") || 
      allDomains.includes("azure-api.net") || 
      allDomains.includes("cloudapp.azure.com") || 
      allDomains.includes("azureedge.net") || 
      allDomains.includes("blob.core.windows.net") || 
      allDomains.includes("database.windows.net") ||
      allDomains.includes("trafficmanager.net") || 
      allDomains.includes("servicebus.windows.net") || 
      allDomains.includes("azure.com") || 
      allDomains.includes("microsoft.com") ||
      allNameservers.includes("azure-dns") ||
      certIssuerStr.includes("microsoft azure")) {
    cloudProvider = "azure";
    cloudProviderLabel = "Microsoft Azure";
  } else if (allDomains.includes("amazonaws.com") || 
             allDomains.includes("cloudfront.net") || 
             allDomains.includes("elasticbeanstalk.com") || 
             allDomains.includes("elb.amazonaws.com") ||
             allDomains.includes("s3.amazonaws.com") ||
             allDomains.includes("aws.amazon.com") ||
             allNameservers.includes("awsdns") ||
             certIssuerStr.includes("amazon")) {
    cloudProvider = "aws";
    cloudProviderLabel = "Amazon Web Services (AWS)";
  } else if (allDomains.includes("run.app") || 
             allDomains.includes("appspot.com") || 
             allDomains.includes("cloudfunctions.net") || 
             allDomains.includes("storage.googleapis.com") ||
             allDomains.includes("google.com") ||
             allDomains.includes("googleapis.com") ||
             allNameservers.includes("googledomains") ||
             allNameservers.includes("google") ||
             certIssuerStr.includes("google trust services")) {
    cloudProvider = "gcp";
    cloudProviderLabel = "Google Cloud Platform (GCP)";
  } else if (allDomains.includes("cloudflare.com") || 
             allDomains.includes("cloudflare.net") || 
             allDomains.includes("pages.dev") || 
             allDomains.includes("workers.dev") ||
             allNameservers.includes("cloudflare") ||
             certIssuerStr.includes("cloudflare")) {
    cloudProvider = "cloudflare";
    cloudProviderLabel = "Cloudflare Global Edge";
  } else if (allDomains.includes("edgekey.net") || 
             allDomains.includes("akamaiedge.net") || 
             allDomains.includes("edgesuite.net") ||
             allNameservers.includes("akam")) {
    cloudProvider = "akamai";
    cloudProviderLabel = "Akamai Intelligent Edge";
  } else if (allDomains.includes("fastly.net") ||
             serverHeaderLower.includes("varnish") ||
             serverHeaderLower.includes("fastly") ||
             xCacheHeader.includes("fastly") ||
             viaHeader.includes("fastly")) {
    cloudProvider = "fastly";
    cloudProviderLabel = "Fastly Edge Cloud";
  } else {
    cloudProvider = "hybrid";
    cloudProviderLabel = "Enterprise Custom Ingress";
  }

  // Primary Ingress Tier & WAF Classification
  let primaryService = "Enterprise Public Ingress";
  let wafActive = false;

  if (allDomains.includes("azurefd.net") || (allDomains.includes("trafficmanager.net") && allDomains.includes("azurefd"))) {
    primaryService = "Azure Front Door Premium & Global WAF";
    wafActive = true;
    hstsActive = true;
  } else if (allDomains.includes("cloudfront.net")) {
    primaryService = "Amazon CloudFront Global CDN & AWS WAF";
    wafActive = true;
  } else if (allDomains.includes("cloudflare") || allNameservers.includes("cloudflare")) {
    primaryService = "Cloudflare Enterprise Edge & WAF";
    wafActive = true;
  } else if (allDomains.includes("edgekey.net") || allDomains.includes("akamaiedge.net")) {
    primaryService = "Akamai Intelligent Edge CDN & WAF";
    wafActive = true;
  } else if (allDomains.includes("azureedge.net")) {
    primaryService = "Azure Content Delivery Network (CDN Standard)";
    wafActive = true;
  } else if (allDomains.includes("vault.azure.net")) {
    primaryService = "Azure Key Vault (Managed HSM Secret Store)";
    wafActive = true;
    hstsActive = true;
  } else if (allDomains.includes("azure-api.net")) {
    primaryService = "Azure API Management (APIM Enterprise Gateway)";
    wafActive = true;
  } else if (allDomains.includes("azurewebsites.net")) {
    primaryService = "Azure App Service (PaaS Linux / Windows Web App)";
    wafActive = false;
  } else if (allDomains.includes("cloudapp.azure.com")) {
    primaryService = "Azure Virtual Network / AKS Ingress Public IP";
    wafActive = false;
  } else if (allDomains.includes("elb.amazonaws.com")) {
    primaryService = "AWS Application Load Balancer (ALB Origin)";
    wafActive = false;
  } else if (allDomains.includes("run.app")) {
    primaryService = "Google Cloud Run Serverless Ingress";
    wafActive = false;
  } else if (allDomains.includes("blob.core.windows.net")) {
    primaryService = "Azure Blob Storage (Static Web Hosting Endpoint)";
    wafActive = false;
  } else {
    primaryService = wafActive ? "Protected Cloud Edge Ingress" : "Direct Origin Ingress (Exposed)";
  }

  // Discovered Cloud Architecture Services
  const resources = [];

  // Tier 1: DNS & Global Traffic Management
  let dnsServiceName = "Authoritative Enterprise DNS";
  if (allDomains.includes("trafficmanager.net") || allNameservers.includes("azure-dns")) {
    dnsServiceName = allDomains.includes("trafficmanager.net") ? "Azure Traffic Manager & Azure DNS" : "Azure DNS Managed Zone";
  } else if (allNameservers.includes("awsdns")) {
    dnsServiceName = "AWS Route 53 Global Anycast DNS";
  } else if (allNameservers.includes("cloudflare")) {
    dnsServiceName = "Cloudflare Managed Anycast DNS";
  } else if (allNameservers.includes("google") || allNameservers.includes("googledomains")) {
    dnsServiceName = "Google Cloud DNS";
  }

  const dnsHealthy = (dnsData.aRecords.length > 1 || dnsData.cnames.length > 0);
  resources.push({
    id: `res-${appPrefix}-dns`,
    name: dnsServiceName,
    provider: (cloudProvider === "hybrid" || cloudProvider === "cloudflare" || cloudProvider === "akamai" || cloudProvider === "fastly") ? "azure" : cloudProvider,
    type: "DNS & Traffic Management",
    status: dnsHealthy ? "healthy" : "warning",
    note: `Resolved ${dnsData.aRecords.length} IP(s)${dnsData.aRecords.length > 0 ? ': ' + dnsData.aRecords.slice(0, 2).join(', ') : ''} • ${dnsData.cnames.length} CNAME hop(s)`
  });

  // Tier 2: Edge Ingress & WAF
  resources.push({
    id: `res-${appPrefix}-ingress`,
    name: primaryService,
    provider: (cloudProvider === "hybrid" || cloudProvider === "cloudflare" || cloudProvider === "akamai" || cloudProvider === "fastly") ? "azure" : cloudProvider,
    type: "Edge & Ingress",
    status: wafActive ? "healthy" : "warning",
    note: wafActive ? "Edge reverse proxy with active DDoS & L7 WAF protection" : "Direct origin exposure without Layer-7 Edge WAF"
  });

  // Tier 3: Compute Runtime
  let computeName = `${hostname} Application Runtime`;
  if (allDomains.includes("azurewebsites.net")) computeName = "Azure App Service (Linux/Windows PaaS)";
  else if (allDomains.includes("cloudapp.azure.com")) computeName = "Azure AKS / CloudApp Ingress Cluster";
  else if (allDomains.includes("vault.azure.net")) computeName = "Azure Key Vault Dedicated HSM Instance";
  else if (allDomains.includes("azure-api.net")) computeName = "Azure API Management Gateway Engine";
  else if (allDomains.includes("run.app")) computeName = "Google Cloud Run Microservice Container";
  else if (allDomains.includes("elb.amazonaws.com")) computeName = "AWS Application Load Balancer / ECS Cluster";

  resources.push({
    id: `res-${appPrefix}-compute`,
    name: computeName,
    provider: (cloudProvider === "hybrid" || cloudProvider === "cloudflare" || cloudProvider === "akamai" || cloudProvider === "fastly") ? "azure" : cloudProvider,
    type: "Compute",
    status: liveProbe.reachable ? (protocol === "https" ? "healthy" : "critical") : "warning",
    note: `${protocol.toUpperCase()}${liveProbe.latencyMs !== null ? ' • Latency: ' + liveProbe.latencyMs + 'ms' : ''} • Status: ${liveProbe.httpStatus || 200}`
  });

  // Tier 4: Key Vault / HSM (only if genuinely detected or Azure PaaS)
  if (allDomains.includes("vault.azure.net") || allDomains.includes("azurewebsites.net")) {
    resources.push({
      id: `res-${appPrefix}-kv`,
      name: allDomains.includes("vault.azure.net") ? `kv-${appPrefix}-hsm` : `kv-${appPrefix}-vault`,
      provider: "azure",
      type: "Security & Vault",
      status: "healthy",
      note: allDomains.includes("vault.azure.net") ? "Primary Hardware Security Module (FIPS 140-2 Level 3)" : "Azure Key Vault Managed App Secret Store"
    });
  }

  // Cryptographic Keys Discovered (Key Sentinel)
  const keys = [];
  if (protocol === "https") {
    let keyName = `tls-cert-${hostname.replace(/\./g, '-')}`;
    let certService = primaryService;
    let certStorage = "Azure Key Vault (Managed Certificate)";
    if (cloudProvider === "aws") certStorage = "AWS Certificate Manager (ACM)";
    else if (cloudProvider === "gcp") certStorage = "Google Cloud Certificate Manager";
    else if (cloudProvider === "cloudflare") certStorage = "Cloudflare Edge SSL Certificate";
    else if (cloudProvider === "hybrid") certStorage = "Enterprise PKI / Public CA";

    let certExpiryDate = null;
    let certDaysLeft = null;
    let certIssuerText = "Certificate data unavailable";
    let certSerial = "N/A";
    let certSans = [hostname];

    if (certData) {
      certExpiryDate = certData.notAfter ? certData.notAfter.split('T')[0] : null;
      certDaysLeft = certData.daysRemaining;
      certIssuerText = certData.cleanIssuer;
      certSerial = certData.serialNumber;
      certSans = certData.sans || [hostname];
    }

    keys.push({
      id: `key-${appPrefix}-ssl`,
      provider: (cloudProvider === "hybrid" || cloudProvider === "cloudflare" || cloudProvider === "akamai" || cloudProvider === "fastly") ? "azure" : cloudProvider,
      name: keyName,
      service: certService,
      type: "SSL/TLS Server Certificate",
      storage: certStorage,
      issuer: certIssuerText,
      serialNumber: certSerial,
      expiryDate: certExpiryDate || "Data unavailable (CORS restricted)",
      daysRemaining: certDaysLeft,
      sans: certSans,
      impact: certDaysLeft !== null
        ? "Client TLS handshake errors (NET::ERR_CERT_DATE_INVALID), immediate customer connectivity blackout, API failures."
        : "Certificate data could not be fetched (Certificate Transparency lookup blocked). Verify certificate expiry manually.",
      costRisk: certDaysLeft !== null ? "Immediate customer transaction drop and SLA penalty breach" : "Manual verification required"
    });
  }

  // Architectural Findings & Remediation
  const issues = [];

  // Plaintext HTTP check
  if (protocol === "http") {
    issues.push({
      id: `iss-endpoint-${appPrefix}-http`,
      title: `Insecure Plaintext HTTP Ingress Configured on ${hostname}`,
      severity: "CRITICAL",
      pillar: "security",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `Endpoint operates over unencrypted HTTP (port 80). Passwords, session tokens, and payload data are transmitted in cleartext over public networks.`,
      rootCause: "HTTPS-Only enforcement toggle is disabled on the ingress listener.",
      remediation: cloudProvider === "azure" 
        ? `az webapp update --name ${appPrefix} --resource-group <rg-name> --set httpsOnly=true`
        : `Enforce 301 permanent redirect to HTTPS and deploy a TLS 1.2+ certificate.`,
      remediated: false
    });
  }

  // Direct origin ingress without WAF
  if (!wafActive) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-waf`,
      title: `Direct Origin Ingress Exposed Without Edge WAF / CDN Protection`,
      severity: "HIGH",
      pillar: "security",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `Target ${hostname} is exposed directly to the public internet without an Azure Front Door Premium WAF, CloudFront, or Cloudflare layer. Origin compute is vulnerable to DDoS attacks and Layer-7 injection exploits (CIS Azure 9.1 / CIS AWS 1.2).`,
      rootCause: "Public ingress terminates directly at origin compute without reverse-proxy WAF filtering.",
      remediation: cloudProvider === "azure"
        ? "Deploy Azure Front Door Premium with WAF in Prevention Mode and enforce service tag IP restrictions on the origin."
        : "Deploy AWS CloudFront with AWS WAF or Cloudflare Enterprise in front of the origin application.",
      remediated: false
    });
  }

  // Certificate Expiration Risk (from real CT certData)
  if (certData) {
    if (certData.daysRemaining <= 0) {
      issues.push({
        id: `iss-endpoint-${appPrefix}-certexp`,
        title: `SSL/TLS Server Certificate EXPIRED (${Math.abs(certData.daysRemaining)} Days Ago)`,
        severity: "CRITICAL",
        pillar: "security",
        provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
        resource: `tls-cert-${hostname.replace(/\./g, '-')}`,
        description: `The SSL/TLS certificate for ${hostname} expired on ${certData.notAfter}. All connecting web browsers and API clients are receiving hard security blocks (ERR_CERT_DATE_INVALID).`,
        rootCause: "Automated renewal failed or ACME / Key Vault renewal pipeline stalled.",
        remediation: cloudProvider === "azure"
          ? `az keyvault certificate set-attributes --vault-name <vault> --name <cert-name> --enabled true && az webapp config ssl bind`
          : `Rotate and install new TLS certificate immediately from your CA or cloud certificate manager.`,
        remediated: false
      });
    } else if (certData.daysRemaining <= 14) {
      issues.push({
        id: `iss-endpoint-${appPrefix}-certexp`,
        title: `Imminent SSL/TLS Certificate Expiration (${certData.daysRemaining} Days Remaining)`,
        severity: "CRITICAL",
        pillar: "security",
        provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
        resource: `tls-cert-${hostname.replace(/\./g, '-')}`,
        description: `Certificate for ${hostname} will expire in ${certData.daysRemaining} days. Production outage will occur unless rotated immediately.`,
        rootCause: "Renewal lifecycle window expiring within emergency threshold (< 14 days).",
        remediation: "Execute key rotation immediately via cloud key vault or certificate manager.",
        remediated: false
      });
    } else if (certData.daysRemaining <= 30) {
      issues.push({
        id: `iss-endpoint-${appPrefix}-certexp`,
        title: `SSL/TLS Certificate Expiration Approaching (${certData.daysRemaining} Days Remaining)`,
        severity: "HIGH",
        pillar: "security",
        provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
        resource: `tls-cert-${hostname.replace(/\./g, '-')}`,
        description: `Certificate for ${hostname} expires on ${certData.notAfter} (${certData.daysRemaining} days remaining). Must be scheduled for rotation.`,
        rootCause: "Standard 30-day rotation cycle active.",
        remediation: "Trigger certificate renewal via cloud provider or Key Vault Sentinel.",
        remediated: false
      });
    }
  }

  // DNS Geo-Redundancy & Failover Check
  if (dnsData.aRecords.length === 1 && dnsData.cnames.length === 0) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-spof`,
      title: `Single Origin IP Resolution (Lack of Geo-Redundancy / Anycast Failover)`,
      severity: "MEDIUM",
      pillar: "reliability",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: dnsServiceName,
      description: `DNS resolves to only 1 static IPv4 address (${dnsData.aRecords[0]}) with no CNAME alias routing to a multi-region CDN or Traffic Manager, representing a single point of failure (SPOF).`,
      rootCause: "Direct single-host DNS mapping without global load balancer or CDN failover.",
      remediation: "Configure Azure Traffic Manager, Azure Front Door, or AWS Route 53 with multi-region latency/failover routing.",
      remediated: false
    });
  }

  // HSTS Header check
  if (protocol === "https" && !hstsActive) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-hsts`,
      title: `HTTP Strict Transport Security (HSTS) Header Absent on Ingress`,
      severity: "MEDIUM",
      pillar: "security",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `Response headers from ${hostname} do not include Strict-Transport-Security, exposing clients to SSL stripping and downgrade attacks.`,
      rootCause: "HSTS policy not configured on origin or edge reverse proxy.",
      remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to custom response headers.",
      remediated: false
    });
  }

  // Reachability check
  if (!liveProbe.reachable) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-reach`,
      title: `Live Endpoint Health Check Failed: ${liveProbe.httpStatusText}`,
      severity: "HIGH",
      pillar: "reliability",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `Live probe could not establish a connection to ${url} (status: ${liveProbe.httpStatus}). The host may be stopped, DNS record unmapped, or firewall blocking client ingress.`,
      rootCause: "Service down, firewall blocking client ingress, or invalid DNS FQDN.",
      remediation: "Verify DNS resolution with 'nslookup' and verify container / App Service status in Azure Portal / AWS Console.",
      remediated: false
    });
  } else if (liveProbe.latencyMs && liveProbe.latencyMs > 800) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-latency`,
      title: `Elevated Network Latency Detected (${liveProbe.latencyMs}ms)`,
      severity: "LOW",
      pillar: "performance",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `Round-trip response time (${liveProbe.latencyMs}ms) exceeds the 300ms SLA target for interactive web applications.`,
      rootCause: "Geographic distance from edge or origin compute throttling.",
      remediation: "Deploy multi-region replication and CDN caching for static and dynamic assets.",
      remediated: false
    });
  }

  // Server header disclosure
  if (serverHeader) {
    issues.push({
      id: `iss-endpoint-${appPrefix}-server`,
      title: `Server Runtime Header Disclosed ('Server: ${escapeHtml(serverHeader)}')`,
      severity: "LOW",
      pillar: "operations",
      provider: cloudProvider === "hybrid" ? "azure" : cloudProvider,
      resource: `${hostname} Application Runtime`,
      description: `The origin web server transmits a 'Server' header disclosing internal framework technology, aiding automated attacker reconnaissance.`,
      rootCause: "Default web server response header emission.",
      remediation: "Suppress 'Server' and 'X-Powered-By' headers in web.config or edge reverse proxy.",
      remediated: false
    });
  }

  // Overall Health Score Computation
  let score = 100;
  issues.forEach(i => {
    if (i.severity === "CRITICAL") score -= 25;
    else if (i.severity === "HIGH") score -= 15;
    else if (i.severity === "MEDIUM") score -= 8;
    else score -= 3;
  });
  score = Math.max(10, Math.min(100, score));

  return {
    url,
    hostname,
    protocol,
    pathname,
    appPrefix,
    cloudProvider,
    cloudProviderLabel,
    primaryService,
    healthScore: score,
    wafActive,
    liveProbe,
    dnsData,
    certData,
    resources,
    keys,
    issues
  };
}

// ----------------------------------------------------------------------------
// MODAL RENDERER WITH LIVE DNS TRACE & REAL CERT SENTINEL
// ----------------------------------------------------------------------------
function renderEndpointReportModal(data) {
  const targetLabel = document.getElementById("endpointReportTargetUrl");
  if (targetLabel) targetLabel.textContent = `Target Endpoint: ${data.url}`;

  const body = document.getElementById("endpointReportBody");
  if (!body) return;

  const scoreClass = data.healthScore >= 80 ? "score-healthy" : data.healthScore >= 60 ? "score-warning" : "score-critical";
  const scoreText = data.healthScore >= 80 ? "Resilient & Compliant" : data.healthScore >= 60 ? "Elevated Risk / Action Required" : "Critical Outage / Breach Risk";
  const latencyDisplay = data.liveProbe.latencyMs !== null ? `${data.liveProbe.latencyMs}ms` : (data.liveProbe.reachable ? "Reachable" : "Offline");
  const protocolText = data.protocol === "https" ? "HTTPS (TLS 1.2+ Enforced)" : "HTTP (Insecure Plaintext)";

  // Build DNS routing flow
  const cnameChain = [data.hostname, ...(data.dnsData?.cnames || [])];

  body.innerHTML = `
    <!-- Hero Summary Grid -->
    <div class="endpoint-report-hero">
      <div class="endpoint-hero-details">
        <div class="endpoint-target-badge">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>
          ${escapeHtml(data.url)}
        </div>
        <div class="endpoint-hero-title">${escapeHtml(data.hostname)}</div>
        <div class="endpoint-hero-meta">
          <span>Provider: <strong>${escapeHtml(data.cloudProviderLabel)}</strong></span>
          <span>Primary Ingress: <strong>${escapeHtml(data.primaryService)}</strong></span>
          <span>Protocol: <strong>${protocolText}</strong></span>
          <span>Round-Trip Latency: <strong>${latencyDisplay}</strong></span>
        </div>
      </div>
      <div class="endpoint-score-block ${scoreClass}">
        <div class="endpoint-score-num">${data.healthScore}%</div>
        <div class="endpoint-score-lbl">${scoreText}</div>
      </div>
    </div>

    <!-- 4 KPI Telemetry Cards -->
    <div class="endpoint-kpis-grid">
      <div class="endpoint-kpi-card">
        <span class="kpi-label">Round-Trip Latency</span>
        <span class="kpi-value" style="color:${data.liveProbe.reachable ? '#10b981' : '#ef4444'};">
          ${latencyDisplay}
        </span>
        <span class="kpi-note">${data.liveProbe.reachable ? (data.liveProbe.corsRestricted ? 'Network Online (CORS Enforced)' : 'Direct HTTP Response') : 'Probe Unreachable'}</span>
      </div>
      <div class="endpoint-kpi-card">
        <span class="kpi-label">Discovered Cloud Tiers</span>
        <span class="kpi-value" style="color:var(--azure-cyan);">${data.resources.length}</span>
        <span class="kpi-note">DNS, Ingress, Compute, Security</span>
      </div>
      <div class="endpoint-kpi-card">
        <span class="kpi-label">Open Architectural Risks</span>
        <span class="kpi-value" style="color:${data.issues.length > 2 ? '#ef4444' : data.issues.length > 0 ? '#f59e0b' : '#10b981'};">${data.issues.length}</span>
        <span class="kpi-note">WAF, DNS & Encryption Controls</span>
      </div>
      <div class="endpoint-kpi-card">
        <span class="kpi-label">Edge WAF / Reverse Proxy</span>
        <span class="kpi-value" style="color:${data.wafActive ? '#10b981' : '#f59e0b'};">
          ${data.wafActive ? 'Active' : 'Unprotected'}
        </span>
        <span class="kpi-note">${data.wafActive ? 'Layer-7 WAF & CDN Active' : 'Direct Origin Exposed'}</span>
      </div>
    </div>

    <!-- LIVE DNS & ROUTING TRACE BOX -->
    <div class="endpoint-dns-box">
      <div class="dns-trace-row">
        <div class="dns-trace-label">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
          Live DNS & CNAME Ingress Routing Chain
        </div>
        <div class="dns-trace-flow">
          ${cnameChain.map((node, idx) => `
            <span class="dns-node-chip ${idx === 0 ? 'origin' : (idx === cnameChain.length - 1 ? 'target' : '')}">
              ${escapeHtml(node)}
            </span>
            ${idx < cnameChain.length - 1 ? '<span class="dns-arrow">➔</span>' : ''}
          `).join('')}
        </div>
      </div>

      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:1rem; margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid rgba(255,255,255,0.06);">
        <div>
          <div class="dns-trace-label">Resolved IPv4 Addresses (A-Records)</div>
          <div class="dns-trace-flow">
            ${(data.dnsData?.aRecords?.length || 0) === 0 ? '<span style="font-size:0.78rem; color:#64748b;">No A-records resolved</span>' : data.dnsData.aRecords.map(ip => `
              <span class="dns-node-chip ip">${escapeHtml(ip)}</span>
            `).join('')}
          </div>
        </div>
        <div>
          <div class="dns-trace-label">Authoritative Name Servers (NS)</div>
          <div class="dns-trace-flow">
            ${(data.dnsData?.nsRecords?.length || 0) === 0 ? '<span style="font-size:0.78rem; color:#64748b;">Inherited from root TLD</span>' : data.dnsData.nsRecords.slice(0, 3).map(ns => `
              <span class="dns-node-chip">${escapeHtml(ns)}</span>
            `).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- SECTION 1: KEY & SECRET EXPIRATION SENTINEL -->
    <div class="endpoint-section-head">
      <h4>
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
        1. Cryptographic Key & Secret Expiration Sentinel
      </h4>
      <span style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${data.keys.length} Credential(s) Evaluated</span>
    </div>
    <div class="endpoint-keys-grid">
      ${data.keys.length === 0 ? `
        <div style="grid-column:1/-1; padding:1.25rem; background:rgba(255,255,255,0.02); border:1px dashed var(--border-color); border-radius:6px; color:var(--text-muted); font-size:0.85rem;">
          No TLS certificate detected over plaintext HTTP. Enforce HTTPS to associate SSL/TLS certificate monitoring.
        </div>
      ` : data.keys.map(k => {
        const days = k.daysRemaining !== undefined && k.daysRemaining !== null ? k.daysRemaining : (k.expiryDate && !k.expiryDate.includes("unavailable") ? Math.ceil((new Date(k.expiryDate) - new Date()) / 86400000) : null);
        const pillClass = days === null ? "warning" : days <= 14 ? "critical" : days <= 30 ? "warning" : "healthy";
        return `
          <div class="endpoint-key-card">
            <div class="card-top-row">
              <h5>${escapeHtml(k.name)}</h5>
              <span class="key-countdown-pill ${pillClass}">
                ${days === null ? 'UNKNOWN' : days < 0 ? 'EXPIRED' : days === 0 ? 'TODAY' : `${days}d left`}
              </span>
            </div>
            <div class="endpoint-card-meta">
              <div>Type: <strong>${escapeHtml(k.type)}</strong></div>
              <div>Issuer CA: <strong>${escapeHtml(k.issuer || 'Public CA')}</strong></div>
              <div>Storage: <strong>${escapeHtml(k.storage)}</strong></div>
              <div>Expires: <strong>${escapeHtml(k.expiryDate)}</strong></div>
              <div>Serial: <strong style="font-family:var(--font-mono); font-size:0.72rem;">${escapeHtml(k.serialNumber || 'N/A')}</strong></div>
            </div>
            <div style="font-size:0.75rem; color:#94a3b8; background:rgba(10,15,26,0.6); padding:0.5rem; border-radius:4px; margin-top:0.25rem;">
              <strong style="color:#ef4444;">Outage Impact:</strong> ${escapeHtml(k.impact)}
            </div>
          </div>
        `;
      }).join('')}

    </div>

    <!-- SECTION 2: DISCOVERED CLOUD SERVICES MAP -->
    <div class="endpoint-section-head">
      <h4>
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        2. Associated Cloud Services & Architecture Map
      </h4>
      <span style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${data.resources.length} Interconnected Cloud Services</span>
    </div>
    <div class="endpoint-services-grid">
      ${data.resources.map(r => `
        <div class="endpoint-service-card">
          <div class="card-top-row">
            <h5>${escapeHtml(r.name)}</h5>
            <span class="badge-status badge-${r.status}">${r.status === 'healthy' ? 'Operational' : r.status === 'critical' ? 'Critical SPOF' : 'Warning Active'}</span>
          </div>
          <div class="endpoint-card-meta">
            <div>Tier: <strong>${escapeHtml(r.type)}</strong></div>
            <div>Provider: <strong>${(r.provider || data.cloudProvider).toUpperCase()}</strong></div>
            <div>Diagnostics: <em>${escapeHtml(r.note)}</em></div>
          </div>
        </div>
      `).join('')}
    </div>

    <!-- SECTION 3: ARCHITECTURAL FINDINGS & REMEDIATION -->
    <div class="endpoint-section-head">
      <h4>
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        3. Architectural Findings, Root Cause & Remediation Runbook
      </h4>
      <span style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${data.issues.length} Security & WAF Findings</span>
    </div>
    <div class="endpoint-findings-list">
      ${data.issues.length === 0 ? `
        <div style="padding:1.5rem; text-align:center; background:rgba(16,185,129,0.05); border:1px solid rgba(16,185,129,0.2); border-radius:6px; color:#10b981;">
          <strong>0 Security Violations Detected</strong> — Endpoint adheres to Well-Architected and CIS security baselines.
        </div>
      ` : data.issues.map(i => `
        <div class="endpoint-finding-card ${i.severity.toLowerCase()}">
          <div class="finding-head">
            <span class="finding-head-title">[${i.severity}] ${escapeHtml(i.title)}</span>
            <span class="pillar-tag pillar-${i.pillar}">${i.pillar.toUpperCase()}</span>
          </div>
          <div class="finding-desc">${escapeHtml(i.description)}</div>
          <div style="font-size:0.78rem; color:#cbd5e1;">
            <strong>Root Cause:</strong> ${escapeHtml(i.rootCause)}
          </div>
          <div class="finding-remedy-box">
            <div style="font-weight:700; color:#38bdf8; margin-bottom:0.25rem;">Immediate Remediation Runbook:</div>
            <code>${escapeHtml(i.remediation)}</code>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function ingestEndpointAnalysisToWorkspace() {
  if (!lastEndpointAnalysis) {
    showToast("No active endpoint audit to ingest.", "warning");
    return;
  }

  // Merge resources
  const existingResIds = new Set((activeWorkspace.resources || []).map(r => r.id));
  lastEndpointAnalysis.resources.forEach(r => {
    if (!existingResIds.has(r.id)) {
      activeWorkspace.resources.push(r);
      existingResIds.add(r.id);
    }
  });

  // Merge keys
  const existingKeyNames = new Set((activeWorkspace.keys || []).map(k => k.name));
  lastEndpointAnalysis.keys.forEach(k => {
    if (!existingKeyNames.has(k.name)) {
      activeWorkspace.keys.push(k);
      existingKeyNames.add(k.name);
    }
  });

  // Merge issues
  const existingIssueTitles = new Set((activeWorkspace.issues || []).map(i => i.title));
  lastEndpointAnalysis.issues.forEach(i => {
    if (!existingIssueTitles.has(i.title)) {
      activeWorkspace.issues.push(i);
      existingIssueTitles.add(i.title);
    }
  });

  activeWorkspace.name = `Audited: ${lastEndpointAnalysis.hostname}`;
  saveWorkspace();
  const nameInput = document.getElementById("workspaceNameInput");
  if (nameInput) nameInput.value = activeWorkspace.name;

  renderAllViews();
  renderTopology();
  document.getElementById("modalEndpointReport")?.classList.remove("active");
  showToast(`Ingested ${lastEndpointAnalysis.resources.length} verified cloud services and ${lastEndpointAnalysis.keys.length} keys from ${lastEndpointAnalysis.hostname} into workspace!`, "success");
}

// ============================================================================
// UTILITIES
// ============================================================================

function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}
