# Design Document: IDPS Configuration and Policy Deployment

## 1. Objective
Configure and deploy an Intrusion Detection and Prevention System (IDPS)
capable of detecting common attack patterns, applying severity-based
response policies, and producing SOC-style alert reports — demonstrating
the core workflow used with production tools like Suricata/Snort.

## 2. Scope
- Signature-based detection (not anomaly/ML-based)
- Simulated network traffic (safe to run on any machine, no live traffic needed)
- Policy-driven response: log, alert, or block per severity level
- Alert logging and reporting suitable for SOC review

## 3. Architecture

```
 ┌─────────────────┐     ┌──────────────────┐     ┌───────────────┐
 │ Traffic Source    │ --> │ Detection Engine  │ --> │ Policy Engine  │
 │ (simulated events) │     │ (rule matching)    │     │ (severity→action)│
 └─────────────────┘     └──────────────────┘     └───────┬───────┘
                                                            │
                                          ┌─────────────────┴─────────────────┐
                                          v                                   v
                                  ┌───────────────┐                 ┌────────────────┐
                                  │ Alert Logging   │                 │ Reporting        │
                                  │ (alerts.log)     │                 │ (report.md)       │
                                  └───────────────┘                 └────────────────┘
```

## 4. Detection Rules (rules.json)

| ID   | Name                          | Logic                                              | Severity |
|------|-------------------------------|-----------------------------------------------------|----------|
| R001 | Port Scan Detection            | ≥10 distinct destination ports from one src IP within 5s | High     |
| R002 | Blacklisted IP Connection       | Source IP matches a known-bad IP list                | Critical |
| R003 | Malicious Payload Signature     | Payload contains known attack strings (SQLi, XSS, etc.) | High     |
| R004 | SSH Brute Force Attempt          | ≥5 connection attempts to port 22 from one IP within 10s | Medium   |
| R005 | Suspicious/Backdoor Port Access | Connection to a known malicious port (4444, 31337, 6667) | Critical |

Rules are configuration data, not hardcoded logic — new rules can be added
to `rules.json` without touching the engine code, which mirrors how real
IDPS rule management works (rule sets are updated independently of the engine).

## 5. Policy Design (policy.json)

| Severity | Action | Rationale                                            |
|----------|--------|-------------------------------------------------------|
| Critical | Block  | Immediate containment for known-bad indicators (backdoors, blacklisted IPs) |
| High     | Alert  | Needs analyst review but not auto-blocked (avoids false-positive lockouts, e.g. legitimate scans) |
| Medium   | Log    | Recorded for trend analysis/correlation, low immediate risk |
| Low      | Log    | Baseline/informational events                          |

This separation reflects a real SOC tuning decision: auto-blocking should be
reserved for high-confidence indicators, while lower-confidence signals go to
an analyst queue to avoid disrupting legitimate traffic.

## 6. Testing Methodology
`traffic_generator.py` produces a deterministic mix of:
- Normal background traffic (should generate zero alerts)
- One instance of each attack pattern (R001–R005)

This allows repeatable testing: every run should trigger exactly one alert
per attack rule, which is used to validate the detection logic works as
configured (equivalent to writing test cases for each Suricata/Snort rule).

## 7. Mapping to Real-World Tools
The rule/policy structure used here maps 1:1 onto real Suricata rule syntax
(see `suricata_reference.rules`):
- Signature content matching → `content:` keyword
- Thresholding (port scan, brute force) → `threshold:` keyword
- Severity/classification → `classtype:` keyword
- Blacklists → IP variable sets in `HOME_NET` / custom IP groups

## 8. Relevant Framework Reference
This project design aligns with **NIST SP 800-94: Guide to Intrusion
Detection and Prevention Systems (IDPS)**, particularly:
- Detection methodology (signature-based)
- Component architecture (sensor, analysis engine, alerting, management)
- Response policy tuning (balancing false positives vs. detection coverage)

## 9. Deliverables
1. This design document
2. Working codebase (Python, stdlib only)
3. Sample `alerts.log` and `report.md` from a test run
4. Reference Suricata rule mapping
5. Short internship write-up connecting design decisions to SOC practice
