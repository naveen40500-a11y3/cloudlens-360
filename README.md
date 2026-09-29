# CloudLens 360° | Enterprise Multi-Cloud Governance & Key Sentinel

CloudLens 360° is an enterprise-grade, client-side diagnostics and governance platform designed for Chief Information Security Officers (CISOs), Principal Cloud Architects, and Enterprise Infrastructure Leaders.

It delivers real-time visibility across **Microsoft Azure**, **Amazon Web Services (AWS)**, and **Google Cloud Platform (GCP)**, featuring automated **Well-Architected Framework (WAF)** pillar scoring, **Key Expiration & Secret Sentinel**, **Interactive Service Topology & Blast Radius** maps, **OmniScan Multi-Cloud IaC / CIS Benchmark Diagnostic Engine**, and an **Executive Audit & Remediation Dossier**.

---

## 🌟 Key Architecture Pillars

### 1. Tri-Cloud Scope & Architecture Profiles
- **Multi-Cloud Scope Ribbon**: Live filtering across All Clouds, Azure, AWS, and GCP with real-time credential, service, and vulnerability tallies.
- **Dynamic Framework Alignment**: Context-aware benchmarking against:
  - *Azure Well-Architected Framework* (Reliability, Security, Cost, Ops, Performance)
  - *AWS Well-Architected Framework* (6 Pillars including Sustainability)
  - *Google Cloud Architecture Framework* (Security, Reliability, Cost, Ops, Performance)
- **Built-in Reference Topologies**:
  - `cross-cloud-mesh`: Cross-Cloud Hybrid Financial Mesh (Azure Front Door edge, AWS Aurora/DynamoDB backplane, GCP Vertex AI/BigQuery analytics).
  - `aws-ecommerce`: High-Velocity Streaming & Retail (CloudFront, EKS, RDS Aurora, IAM, ACM).
  - `gcp-enterprise`: GCP Enterprise AI & Data Platform (Cloud Armor, GKE, Vertex AI, Cloud KMS, Service Accounts).
  - `fintech-core`: High-Throughput FinTech Payment Engine (Azure Tier-1).
  - `global-healthcare`: Multi-Region HIPAA Telehealth Mesh.
  - `ai-genomics`: High-Performance AI/ML Genomics Pipeline.

---

### 2. Key Sentinel & Credential Expiration Radar
- **Proactive Lifecycle Governance**: Continuous countdown tracking for:
  - **Azure**: App Registration Client Secrets, Enterprise SPNs, Key Vault Certificates.
  - **AWS**: IAM Access Keys, KMS Customer Managed Keys (CMKs), ACM Wildcard Certificates.
  - **GCP**: Service Account JSON Keys (GSA), Cloud KMS CryptoKeys, OAuth2 Client Secrets.
- **Color-Coded Urgency Tiers**:
  - `Critical Breach / Expired`: Immediate failover/rotation trigger.
  - `Expiring < 7 Days`: High priority remediation banner.
  - `Expiring < 30 Days`: Scheduled rotation cycle.
  - `Healthy / Automated`: Automated key rotation active.
- **Copy-Paste Remediation Runbooks**: One-click generation of provider-native CLI scripts (`az ad app credential reset`, `aws iam create-access-key`, `gcloud iam service-accounts keys create`).

---

### 3. Live Service Topology & Blast Radius Canvas
- **Interactive HTML5 Canvas Graph**: High-resolution rendering of active workspace services, cloud interconnects, and dependency boundaries.
- **Provider-Themed Badges**: Visual indicator tags (`AZURE`, `AWS`, `GCP`) and custom halo glows for multi-cloud clarity.
- **Blast Radius & Topology Analyzer**: Interactive node selection detailing direct dependents, vulnerability severity, and cascading outage risks with real remediation triggers.

---

### 4. OmniScan Multi-Cloud IaC & Secret Scanner
- **Multi-Format Ingestion**: Scans Terraform (`.tf`), AWS CloudFormation (`.yaml`/`.json`), Azure Resource Manager (`ARM`), and Azure Bicep templates.
- **CIS Benchmark & Vulnerability Rules**:
  - `AWS-S3-001`: Public Read/Write ACLs on S3 Buckets (CIS 2.1.5).
  - `AWS-IAM-002`: Over-privileged Wildcard Policies (`"Action": "*"`).
  - `AWS-KMS-003`: Unencrypted RDS or EBS Storage Volumes.
  - `AWS-RDS-004`: Single-AZ Database Deployments (Single Point of Failure).
  - `GCP-IAM-001`: Insecure `allUsers` Public IAM Bindings or Default Editor Service Accounts.
  - `AZ-NET-001`: Open SSH/RDP NSG Inbound Rules.
- **Dynamic Ingestion**: Ingest scanned vulnerabilities and resources straight into the active workspace with live score re-computation.

---

### 5. Live App URL & Multi-Cloud Architecture Auditor
- **Authentic DNS-over-HTTPS (DoH) Discovery**: Queries Google Public DNS via DoH (`A`, `CNAME`, `NS`, `CAA`, `TXT`) in real-time with zero CORS friction, resolving actual origin IPs and full CNAME alias routing chains (e.g. `Traffic Manager ➔ Front Door ➔ Edge Network`).
- **Accurate Multi-Cloud Fingerprinting**: Accurately classifies provider infrastructure (**Microsoft Azure**, **Amazon Web Services**, **Google Cloud Platform**, **Cloudflare Edge**, **Akamai CDN**, or **Enterprise Custom/Hybrid Ingress**), eliminating false provider defaults.
- **Cryptographic Key & Expiration Sentinel**: Performs live Certificate Transparency (CT) lookups and TLS inspection to discover the genuine issuer CA (e.g., `Microsoft Azure RSA TLS Issuing CA`, `Amazon RSA 2048 M02`, `DigiCert`, `Let's Encrypt`), real expiration horizon, and serial number.
- **Dynamic Architecture Mapping**: Maps authentic discovered tiers (DNS & Traffic Management, Edge Ingress & WAF, Compute Runtime, Key Vault / Certificate Manager) based on live telemetry.
- **Actionable Remediation Runbooks**: Generates provider-native CLI remediation commands (`az webapp update`, `aws acm request-certificate`, `az keyvault certificate set-attributes`) tailored to the discovered provider.
- **One-Click Workspace Ingestion**: Merges the discovered cloud infrastructure, keys, and findings straight into the active workspace, updating the live topology canvas and risk matrix.

---

### 6. Executive Architecture Audit & Remediation Dossier
- **C-Suite Multi-Cloud Posture Report**: Aggregates Tri-Cloud WAF adherence, compliance frameworks (NIST, CIS, PCI-DSS, HIPAA), and unmitigated risk items.
- **Tri-Cloud Governance Breakdown**: Dedicated multi-cloud matrix tracking Azure, AWS, and GCP credential evaluation counts and compliance scores.
- **Print & PDF Export**: Clean, printable executive summary formatted for compliance audits and board presentations.

---

## 🚀 Getting Started

CloudLens 360° is 100% self-contained and operates client-side with **zero build dependencies**:

1. Open `index.html` in any modern web browser (Edge, Chrome, Firefox, Safari).
2. Manage your active workspace directly or import infrastructure from JSON via **Import Inventory / IaC**.
3. Track, rotate, and update cryptographic secrets with live date countdowns in the **Key Sentinel** tab.
4. Scan templates in **OmniScan IaC** and ingest findings into your active workspace.
5. Export full audit JSON or generate executive compliance dossiers anytime from the header controls.

---

## 🛠️ File Structure

```
cloud-architect-diagnostics/
├── index.html        # Single Page Application structure, modals, and tab containers
├── styles.css        # Enterprise dark glassmorphism design system & multi-cloud CSS variables
├── app-main.js       # Dynamic scoring engine, Key Sentinel, canvas topology, & IaC scanner
└── README.md         # Architecture documentation and usage guide
```
