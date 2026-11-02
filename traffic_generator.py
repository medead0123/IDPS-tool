"""
traffic_generator.py
Generates a simulated stream of network events (normal + malicious)
so the IDPS engine can be tested without needing raw packet capture,
root/admin privileges, or a live network.
"""

import time
import random


def generate_traffic():
    events = []
    base_time = time.time()

    # 1. Normal background traffic
    normal_ips = ["10.0.0.5", "10.0.0.8", "10.0.0.12"]
    for i in range(15):
        events.append({
            "src_ip": random.choice(normal_ips),
            "dst_ip": "10.0.0.1",
            "dst_port": random.choice([80, 443, 53]),
            "payload": "GET /index.html HTTP/1.1",
            "timestamp": base_time + i * 0.2,
        })

    # 2. Port scan burst from a single attacker IP
    scanner_ip = "192.168.1.100"
    for port in range(20, 45):
        events.append({
            "src_ip": scanner_ip,
            "dst_ip": "10.0.0.1",
            "dst_port": port,
            "payload": "",
            "timestamp": base_time + 20 + (port - 20) * 0.05,
        })

    # 3. Connection from a blacklisted IP
    events.append({
        "src_ip": "203.0.113.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "payload": "TLS handshake",
        "timestamp": base_time + 25,
    })

    # 4. SQL injection payload attempt
    events.append({
        "src_ip": "10.0.0.20",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "payload": "SELECT * FROM users WHERE id=1 OR 1=1; DROP TABLE users;",
        "timestamp": base_time + 26,
    })

    # 5. SSH brute force burst
    brute_ip = "198.51.100.9"
    for i in range(7):
        events.append({
            "src_ip": brute_ip,
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "payload": "SSH login attempt",
            "timestamp": base_time + 30 + i * 0.5,
        })

    # 6. Connection to a suspicious/backdoor port
    events.append({
        "src_ip": "10.0.0.33",
        "dst_ip": "10.0.0.1",
        "dst_port": 4444,
        "payload": "reverse shell handshake",
        "timestamp": base_time + 40,
    })

    events.sort(key=lambda e: e["timestamp"])
    return events
