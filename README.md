# IDPS Configuration and Policy Deployment (SOC Internship Project)

A lightweight, rule-based Intrusion Detection and Prevention System (IDPS)
built in pure Python (no external libraries needed). It simulates network
traffic, detects malicious patterns using configurable signature rules,
and applies severity-based response policies (log / alert / block).

## How to run

1. Open this folder in VS Code.
2. Make sure Python 3.8+ is installed (`python3 --version`).
3. In the VS Code terminal, run:
   ```
   python main.py
   ```
4. That's it — no pip installs required, everything uses the Python standard library.

## What happens when you run it

- `traffic_generator.py` creates a simulated stream of network events: normal
  traffic plus 5 attack patterns (port scan, blacklisted IP, SQL injection
  payload, SSH brute force, backdoor port access).
- `idps_engine.py` processes each event against the rules in `rules.json`
  and applies the response defined in `policy.json`.
- Alerts print live to the console, get written to `alerts.log` (raw JSON,
  one alert per line), and a human-readable `report.md` is generated at the end.

## Files

| File                       | Purpose                                            |
|-----------------------------|----------------------------------------------------|
| `rules.json`                | Detection rules (signatures/thresholds)            |
| `policy.json`                | Severity → action mapping (log/alert/block)         |
| `traffic_generator.py`      | Generates simulated network events                 |
| `idps_engine.py`             | Core detection + policy engine                     |
| `main.py`                    | Runs the simulation, prints results, builds report  |
| `suricata_reference.rules`  | Same 5 rules written in real Suricata syntax (reference only, not executed) |
| `alerts.log` / `report.md`  | Generated automatically after running               |

## Customizing / extending the project

- Add new rules by adding entries to `rules.json` (supported types:
  `port_scan`, `blacklist_ip`, `payload_match`, `brute_force`, `restricted_port`).
- Change response behavior by editing `policy.json` (e.g. make `medium`
  severity trigger `block` instead of `log`).
- Add more attack scenarios in `traffic_generator.py` to test edge cases.
- For a "real" version, this same rule/policy logic maps directly onto
  Suricata or Snort configuration — see `suricata_reference.rules`.

## Suggested internship deliverables

1. `DESIGN.md` — architecture and rule/policy design (included)
2. This codebase, working and demoed live
3. `alerts.log` and `report.md` from a sample run, as evidence of detection
4. A short write-up: what each rule detects, why the severity/action was
   chosen, and how it maps to NIST SP 800-94 (Guide to IDPS)
5. (Optional bonus) install Suricata in a VM and load `suricata_reference.rules`
   to demonstrate the same logic on a production-grade tool
