"""
idps_engine.py
Core detection + policy engine for the IDPS project.
Loads rules.json and policy.json, processes network events,
raises alerts, applies policy actions (log/alert/block), and writes logs.
"""

import json
import datetime
from collections import defaultdict, deque


class IDPSEngine:
    def __init__(self, rules_path, policy_path, log_path="alerts.log"):
        with open(rules_path) as f:
            self.rules = json.load(f)["rules"]
        with open(policy_path) as f:
            self.policies = json.load(f)["policies"]

        self.alerts = []
        self.blocked_ips = set()
        self.alert_log_path = log_path

        # trackers for stateful/threshold-based rules
        self.port_scan_tracker = defaultdict(deque)
        self.brute_force_tracker = defaultdict(deque)

        # reset log file at start of each run
        open(self.alert_log_path, "w").close()

    def process_event(self, event):
        src_ip = event["src_ip"]

        # If this IP is already blocked by policy, drop it and stop processing
        if src_ip in self.blocked_ips:
            self._log_blocked(event)
            return

        for rule in self.rules:
            rtype = rule["type"]

            if rtype == "blacklist_ip" and src_ip in rule["blacklist"]:
                self._raise_alert(rule, event)

            elif rtype == "payload_match":
                payload = event.get("payload", "")
                for kw in rule["keywords"]:
                    if kw.lower() in payload.lower():
                        self._raise_alert(rule, event, detail=f"matched signature: '{kw}'")
                        break

            elif rtype == "restricted_port" and event.get("dst_port") in rule["ports"]:
                self._raise_alert(rule, event)

            elif rtype == "port_scan":
                self._check_port_scan(rule, event)

            elif rtype == "brute_force":
                self._check_brute_force(rule, event)

    def _check_port_scan(self, rule, event):
        src = event["src_ip"]
        now = event["timestamp"]
        window = rule["window_seconds"]

        dq = self.port_scan_tracker[src]
        dq.append((now, event["dst_port"]))
        while dq and now - dq[0][0] > window:
            dq.popleft()

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= rule["threshold"]:
            self._raise_alert(rule, event, detail=f"{len(distinct_ports)} distinct ports in {window}s")
            dq.clear()

    def _check_brute_force(self, rule, event):
        if event.get("dst_port") != rule["port"]:
            return
        src = event["src_ip"]
        now = event["timestamp"]
        window = rule["window_seconds"]

        dq = self.brute_force_tracker[src]
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()

        if len(dq) >= rule["threshold"]:
            self._raise_alert(rule, event, detail=f"{len(dq)} attempts in {window}s")
            dq.clear()

    def _raise_alert(self, rule, event, detail=""):
        severity = rule["severity"]
        policy = self.policies.get(severity, {"action": "log"})
        action = policy.get("action", "log")

        alert = {
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": severity,
            "src_ip": event["src_ip"],
            "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"),
            "action_taken": action,
            "detail": detail,
        }

        self.alerts.append(alert)

        if action == "block":
            self.blocked_ips.add(event["src_ip"])

        self._write_alert(alert)
        self._print_alert(alert)

    def _log_blocked(self, event):
        line = (f"[BLOCKED] Dropped packet from blocked IP {event['src_ip']} "
                f"-> {event.get('dst_ip')}:{event.get('dst_port')}")
        print(line)
        with open(self.alert_log_path, "a") as f:
            f.write(line + "\n")

    def _write_alert(self, alert):
        with open(self.alert_log_path, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print_alert(self, alert):
        print(f"[{alert['severity'].upper()}] {alert['rule_name']} | "
              f"src={alert['src_ip']} dst={alert['dst_ip']}:{alert['dst_port']} "
              f"action={alert['action_taken']} {alert['detail']}")

    def summary(self):
        by_sev = defaultdict(int)
        for a in self.alerts:
            by_sev[a["severity"]] += 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(by_sev),
            "blocked_ips": sorted(self.blocked_ips),
        }
