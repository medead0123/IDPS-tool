# IDPS Alert Report

**Total Alerts:** 6

## Alerts by Severity
- HIGH: 3
- CRITICAL: 2
- MEDIUM: 1

## Blocked IPs (policy action = block)
- 10.0.0.33
- 203.0.113.5

## Alert Details
| Time | Rule | Severity | Source IP | Action | Detail |
|------|------|----------|-----------|--------|--------|
| 2026-07-15 10:16:56 | Port Scan Detection | high | 192.168.1.100 | alert | 10 distinct ports in 5s |
| 2026-07-15 10:16:56 | Port Scan Detection | high | 192.168.1.100 | alert | 10 distinct ports in 5s |
| 2026-07-15 10:16:56 | Blacklisted IP Connection | critical | 203.0.113.5 | block |  |
| 2026-07-15 10:16:56 | Malicious Payload Signature | high | 10.0.0.20 | alert | matched signature: 'DROP TABLE' |
| 2026-07-15 10:16:56 | SSH Brute Force Attempt | medium | 198.51.100.9 | log | 5 attempts in 10s |
| 2026-07-15 10:16:56 | Suspicious/Backdoor Port Access | critical | 10.0.0.33 | block |  |