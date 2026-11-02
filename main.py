"""
main.py
Entry point: runs the traffic generator through the IDPS engine,
prints a live console feed of alerts, and writes a summary report.

Run with:  python main.py
"""

import json
from traffic_generator import generate_traffic
from idps_engine import IDPSEngine


def generate_report(summary, alerts, path="report.md"):
    lines = ["# IDPS Alert Report", ""]
    lines.append(f"**Total Alerts:** {summary['total_alerts']}")
    lines.append("")
    lines.append("## Alerts by Severity")
    for sev, count in summary["by_severity"].items():
        lines.append(f"- {sev.upper()}: {count}")

    lines.append("")
    lines.append("## Blocked IPs (policy action = block)")
    if summary["blocked_ips"]:
        for ip in summary["blocked_ips"]:
            lines.append(f"- {ip}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Alert Details")
    lines.append("| Time | Rule | Severity | Source IP | Action | Detail |")
    lines.append("|------|------|----------|-----------|--------|--------|")
    for a in alerts:
        lines.append(f"| {a['time']} | {a['rule_name']} | {a['severity']} | "
                      f"{a['src_ip']} | {a['action_taken']} | {a['detail']} |")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    print("=== Starting IDPS Simulation ===\n")

    engine = IDPSEngine("rules.json", "policy.json")
    events = generate_traffic()

    print(f"Processing {len(events)} simulated network events...\n")
    for event in events:
        engine.process_event(event)

    summary = engine.summary()

    print("\n=== Summary ===")
    print(json.dumps(summary, indent=2))

    generate_report(summary, engine.alerts)
    print("\nDone. See 'alerts.log' for raw alert data and 'report.md' for the formatted report.")


if __name__ == "__main__":
    main()
