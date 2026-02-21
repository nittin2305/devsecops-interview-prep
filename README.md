# DevSecOps Senior Interview Prep

> A comprehensive, senior-level interview preparation guide for DevSecOps engineers with 8+ years of experience. Covers principles, tooling, pipelines, cloud security, Kubernetes hardening, compliance, incident response, and leadership — all with real-world examples, Mermaid diagrams, and authoritative citations.

---

## Table of Contents

1. [Repository Overview](#repository-overview)
2. [How to Use This Guide](#how-to-use-this-guide)
3. [Quick Reference Index](#quick-reference-index)
4. [2-Week Study Plan](#2-week-study-plan)
5. [4-Week Study Plan](#4-week-study-plan)
6. [Key Topics Covered](#key-topics-covered)
7. [Contributing](#contributing)

---

## Repository Overview

This repository is designed for experienced engineers preparing for **Senior DevSecOps**, **Principal Security Engineer**, **Platform Security Lead**, or **Staff Security Engineer** interviews. Each file is structured to be:

- **Interview-ready** — Real senior-level Q&A with follow-ups and interviewer rubrics
- **Diagram-rich** — Mermaid diagrams illustrating pipelines, architectures, and decision flows
- **Example-driven** — YAML, Bash, Terraform, and policy-as-code examples throughout
- **Authoritative** — Citations from NIST, OWASP, CNCF, CIS, and vendor documentation
- **Practitioner-focused** — Trade-offs, lessons from production, and opinionated best practices

### Scope

This guide spans the full DevSecOps lifecycle:

```
Plan → Code → Build → Test → Release → Deploy → Operate → Monitor → (back to Plan)
 ↑                                                                           ↓
 └─────────────────── Security Feedback Loop ────────────────────────────────┘
```

---

## How to Use This Guide

1. **Assess your gaps first** — Skim the [Quick Reference Index](#quick-reference-index) and rate yourself 1–5 on each topic. Focus deeper study on topics rated 1–2.
2. **Don't just read — practice** — For every Q&A section, close the answer and try to articulate it yourself before reading the provided answer.
3. **Run the examples** — Every YAML/Bash snippet is production-tested or closely mirrors production patterns. Spin up a local environment to practice.
4. **Draw the diagrams** — Recreate the Mermaid diagrams from memory on a whiteboard. Architecture diagramming is a common senior interview task.
5. **Pair with mock interviews** — Use the Q&A sections to run timed mock interview sessions with a peer.
6. **Update and annotate** — Fork this repo and add your own battle scars, war stories, and edge cases.

---

## Quick Reference Index

### Module 01 — Overview & Principles

| File | Topics | Difficulty |
|------|--------|------------|
| [What is DevSecOps](01-Overview/What-is-DevSecOps.md) | Definition, origin, NIST/OWASP/CNCF frameworks, continuous security loop | ⭐⭐⭐ |
| [DevOps vs DevSecOps](01-Overview/DevOps-vs-DevSecOps.md) | Pipeline comparison, cultural shift, security debt metrics, DORA | ⭐⭐⭐ |
| [Principles & Mental Models](01-Overview/Principles-Mental-Models.md) | Shift-Left, Zero Trust, Defense in Depth, GitOps, Supply Chain | ⭐⭐⭐⭐ |
| [Career Path & Roles](01-Overview/Career-Path-Roles.md) | Role ladders, skills matrix, certifications, leadership competencies | ⭐⭐⭐ |

### Module 02 — CI/CD Pipeline Security *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `02-CICD/Pipeline-Security.md` | SAST, DAST, SCA, secrets scanning, pipeline hardening | ⭐⭐⭐⭐ |
| `02-CICD/GitHub-Actions-Security.md` | OIDC, pinned actions, workflow permissions, SLSA | ⭐⭐⭐⭐ |
| `02-CICD/Supply-Chain-SLSA.md` | SLSA levels, SBOM, Sigstore, in-toto | ⭐⭐⭐⭐⭐ |

### Module 03 — Container & Kubernetes Security *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `03-Kubernetes/Pod-Security.md` | PSA, securityContext, OPA/Gatekeeper, Kyverno | ⭐⭐⭐⭐ |
| `03-Kubernetes/RBAC-Deep-Dive.md` | ClusterRoles, impersonation, audit logs, privilege escalation | ⭐⭐⭐⭐⭐ |
| `03-Kubernetes/Network-Policies.md` | Cilium, Calico, mTLS, service mesh security | ⭐⭐⭐⭐ |
| `03-Kubernetes/CKS-Prep.md` | Full CKS exam domain coverage with labs | ⭐⭐⭐⭐⭐ |

### Module 04 — Cloud Security *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `04-Cloud/AWS-Security.md` | IAM, SCPs, GuardDuty, Security Hub, VPC security | ⭐⭐⭐⭐ |
| `04-Cloud/GCP-Security.md` | Org policies, VPC-SC, CSCC, Workload Identity | ⭐⭐⭐⭐ |
| `04-Cloud/Azure-Security.md` | Entra ID, Defender for Cloud, Policy, Sentinel | ⭐⭐⭐⭐ |
| `04-Cloud/Multi-Cloud-Strategy.md` | CSPM, CWPP, unified identity, data residency | ⭐⭐⭐⭐⭐ |

### Module 05 — Application Security *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `05-AppSec/OWASP-Top10.md` | All 10 categories with DevSecOps mitigations | ⭐⭐⭐ |
| `05-AppSec/Threat-Modeling.md` | STRIDE, PASTA, attack trees, threat modeling in CI/CD | ⭐⭐⭐⭐ |
| `05-AppSec/Secrets-Management.md` | Vault, SOPS, external-secrets, rotation patterns | ⭐⭐⭐⭐ |

### Module 06 — Compliance & Governance *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `06-Compliance/Frameworks-Overview.md` | SOC 2, ISO 27001, PCI-DSS, HIPAA, FedRAMP | ⭐⭐⭐⭐ |
| `06-Compliance/Policy-as-Code.md` | OPA Rego, Conftest, Cedar, CIS Benchmarks | ⭐⭐⭐⭐⭐ |
| `06-Compliance/Audit-Logging.md` | What to log, SIEM integration, retention, immutability | ⭐⭐⭐⭐ |

### Module 07 — Incident Response *(coming soon)*

| File | Topics | Difficulty |
|------|--------|------------|
| `07-Incident-Response/IR-Playbooks.md` | Detection, triage, containment, eradication, recovery | ⭐⭐⭐⭐ |
| `07-Incident-Response/Forensics.md` | Container forensics, memory dumps, log correlation | ⭐⭐⭐⭐⭐ |
| `07-Incident-Response/Chaos-Engineering.md` | Failure injection, security chaos, GameDays | ⭐⭐⭐⭐ |

---

## 2-Week Study Plan

Ideal for engineers with strong DevSecOps foundations who need focused interview prep.

| Day | Morning (1–1.5 hrs) | Evening (1 hr) |
|-----|---------------------|----------------|
| **Day 1** | [What is DevSecOps](01-Overview/What-is-DevSecOps.md) — read + diagram | Practice Q&A 1–5 aloud |
| **Day 2** | [DevOps vs DevSecOps](01-Overview/DevOps-vs-DevSecOps.md) — read + comparison table | Practice Q&A 1–4 aloud |
| **Day 3** | [Principles & Mental Models](01-Overview/Principles-Mental-Models.md) — Shift-Left, Zero Trust | Draw all mental model diagrams from memory |
| **Day 4** | [Principles & Mental Models](01-Overview/Principles-Mental-Models.md) — GitOps, Supply Chain, Defense in Depth | Practice Q&A 6–10 aloud |
| **Day 5** | [Career Path & Roles](01-Overview/Career-Path-Roles.md) + CI/CD Pipeline Security | Behavioral Q&A: leadership & culture |
| **Day 6** | Container & Kubernetes Security (Pod Security, RBAC) | CKS-style: write a NetworkPolicy from scratch |
| **Day 7** | **Review day** — redo all diagrams from memory | Mock interview: 45-min technical session with peer |
| **Day 8** | Cloud Security — AWS IAM deep dive, SCPs, GuardDuty | Write a CloudFormation/Terraform IAM policy |
| **Day 9** | Application Security — OWASP Top 10 with DevSecOps mitigations | Threat model a real system you've worked on |
| **Day 10** | Secrets Management — Vault architecture, rotation, PKI | Configure external-secrets in a local cluster |
| **Day 11** | Compliance — SOC 2 controls mapped to pipeline gates | Write a Conftest policy for a Dockerfile |
| **Day 12** | Incident Response — IR playbook walkthrough | Tabletop: "container escape" scenario |
| **Day 13** | Weak areas review (re-check Day 1–7 gaps) | Behavioral Q&A: conflict, influence without authority |
| **Day 14** | **Full mock interview day** — 2× 45-min sessions | Review feedback, rest |

---

## 4-Week Study Plan

For engineers building or refreshing comprehensive DevSecOps expertise from scratch.

### Week 1 — Foundations & Mental Models

| Day | Focus Area | File(s) |
|-----|-----------|---------|
| Mon | DevSecOps overview & origin story | [What is DevSecOps](01-Overview/What-is-DevSecOps.md) |
| Tue | DevOps vs DevSecOps, DORA metrics, security debt | [DevOps vs DevSecOps](01-Overview/DevOps-vs-DevSecOps.md) |
| Wed | Core principles: Shift-Left, Zero Trust, Least Privilege | [Principles & Mental Models](01-Overview/Principles-Mental-Models.md) |
| Thu | Advanced principles: GitOps, Supply Chain, Immutable Infra | [Principles & Mental Models](01-Overview/Principles-Mental-Models.md) |
| Fri | Career paths, skills matrix, certifications | [Career Path & Roles](01-Overview/Career-Path-Roles.md) |
| Sat | Week 1 review + whiteboard all diagrams | All Module 01 files |
| Sun | Rest / light reading: NIST SP 800-204, CNCF Cloud Native Security Whitepaper | External references |

### Week 2 — CI/CD & Supply Chain Security

| Day | Focus Area | File(s) |
|-----|-----------|---------|
| Mon | SAST, DAST, SCA tools & integration | `02-CICD/Pipeline-Security.md` |
| Tue | GitHub Actions security: OIDC, permissions, pinning | `02-CICD/GitHub-Actions-Security.md` |
| Wed | SLSA levels 1–4, Sigstore, Cosign, SBOM | `02-CICD/Supply-Chain-SLSA.md` |
| Thu | Secrets scanning: Trufflehog, gitleaks, Vault integration | `05-AppSec/Secrets-Management.md` |
| Fri | Hands-on: Build a secure GitHub Actions pipeline end-to-end | Lab |
| Sat | Week 2 review + mock: "secure this pipeline" exercise | — |
| Sun | Rest / read: SLSA specification v1.0, OpenSSF Scorecard docs | External |

### Week 3 — Kubernetes & Cloud Security

| Day | Focus Area | File(s) |
|-----|-----------|---------|
| Mon | Kubernetes Pod Security: PSA, securityContext, AppArmor | `03-Kubernetes/Pod-Security.md` |
| Tue | Kubernetes RBAC: ClusterRoles, audit, privilege escalation paths | `03-Kubernetes/RBAC-Deep-Dive.md` |
| Wed | Network Policies, mTLS, service mesh (Istio/Linkerd) | `03-Kubernetes/Network-Policies.md` |
| Thu | AWS Security: IAM, SCPs, GuardDuty, Security Hub | `04-Cloud/AWS-Security.md` |
| Fri | Cloud misconfig patterns: public S3, overprivileged roles, IMDSv1 | `04-Cloud/AWS-Security.md` |
| Sat | CKS practice exam scenarios | `03-Kubernetes/CKS-Prep.md` |
| Sun | Rest / read: CIS Kubernetes Benchmark v1.8, AWS Security Best Practices | External |

### Week 4 — AppSec, Compliance & Incident Response

| Day | Focus Area | File(s) |
|-----|-----------|---------|
| Mon | OWASP Top 10 with pipeline-level mitigations | `05-AppSec/OWASP-Top10.md` |
| Tue | Threat modeling: STRIDE, PASTA, integrating into sprint planning | `05-AppSec/Threat-Modeling.md` |
| Wed | Compliance frameworks: SOC 2, ISO 27001, FedRAMP mapping | `06-Compliance/Frameworks-Overview.md` |
| Thu | Policy-as-Code: OPA, Rego, Conftest, Gatekeeper | `06-Compliance/Policy-as-Code.md` |
| Fri | Incident Response playbooks + container forensics | `07-Incident-Response/IR-Playbooks.md` |
| Sat | **Full mock interview day** — behavioral + technical | All files |
| Sun | Final review of personal weak areas + rest | Targeted |

---

## Key Topics Covered

```
DevSecOps Fundamentals      CI/CD Security          Container Security
├── Shift-Left Security     ├── SAST/DAST/SCA       ├── Pod Security Admission
├── Zero Trust              ├── Secrets Scanning     ├── RBAC & Audit Logging
├── Defense in Depth        ├── Pipeline Hardening   ├── Network Policies
├── NIST/OWASP/CNCF         ├── SLSA & SBOM          ├── OPA / Kyverno
└── Supply Chain Security   └── Signed Commits       └── Runtime Security

Cloud Security              Application Security    Compliance & Governance
├── IAM Least Privilege     ├── OWASP Top 10        ├── SOC 2 Type II
├── SCPs & Guardrails       ├── Threat Modeling      ├── ISO 27001
├── CSPM / CWPP             ├── Secrets Management   ├── PCI-DSS / HIPAA
├── GuardDuty / Defender    ├── Dependency Auditing  ├── Policy-as-Code
└── VPC & Network Seg.      └── WAF Integration      └── Audit Log Design

Incident Response           Leadership & Culture
├── Detection & Triage      ├── Security Champions
├── Containment             ├── Developer Enablement
├── Forensics               ├── Risk Communication
└── Post-Mortems            └── Metrics & OKRs
```

---

## Contributing

Contributions are welcome from senior practitioners who want to add depth, fix inaccuracies, or extend coverage to new topics.

### Guidelines

1. **Quality bar** — All content must be senior-level. No beginner tutorials. Every claim should be backed by a citation or real-world experience.
2. **Format consistency** — Follow the established file structure:
   - Citations/Sources section at top
   - Conceptual explanation with Mermaid diagrams
   - YAML/Bash examples (production-realistic)
   - Interview Q&A with full answers, follow-ups, and interviewer rubrics
3. **Accuracy** — Do not include outdated information (e.g., deprecated APIs, superseded standards). Include version numbers and dates where relevant.
4. **No vendor lock-in bias** — Where tools are compared, present trade-offs fairly. Acknowledge when a solution is use-case dependent.

### How to Contribute

```bash
# Fork the repository, then:
git clone https://github.com/<your-username>/devsecops-interview-prep
cd devsecops-interview-prep
git checkout -b add/topic-name
# Make your changes
git commit -m "Add: <topic> coverage to <module>"
git push origin add/topic-name
# Open a Pull Request
```

### What We Need Most

- [ ] Module 02: CI/CD Pipeline Security files
- [ ] Module 03: Kubernetes Security files
- [ ] Module 04: Cloud Security (GCP, Azure)
- [ ] Module 05: Application Security files
- [ ] Module 06: Compliance & Governance files
- [ ] Module 07: Incident Response files
- [ ] Real anonymized war stories / postmortems
- [ ] Tool comparison matrices (e.g., Trivy vs Grype vs Snyk)

---

*Maintained by the community. Not affiliated with any vendor. All opinions are those of contributors based on practical experience.*

