#!/usr/bin/env python3
"""
48-Port Network Switch Simulator
Simulates a managed network switch with realistic traffic data
Designed to be polled by Elastic Workflows or any REST client
"""

import random
import time
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Switch Identity ──────────────────────────────────────────────────────────
SWITCH_INFO = {
    "name": "CORE-SW-01",
    "vendor": "Cisco",
    "model": "Catalyst 9300-48P",
    "serial_number": "FCW2347G0AB",
    "software_version": "17.9.4a",
    "firmware_version": "17.9.4a",
    "mac_address": "00:1A:2B:3C:4D:5E",
    "management_ip": "192.168.1.1",
    "location": "Server Room Rack A, Unit 12",
    "boot_time": datetime.now(timezone.utc).isoformat(),
}

BOOT_TIMESTAMP = time.time()

# ── Port State ───────────────────────────────────────────────────────────────
PORT_NAMES = [
    "GigabitEthernet1/0/1",  "GigabitEthernet1/0/2",  "GigabitEthernet1/0/3",
    "GigabitEthernet1/0/4",  "GigabitEthernet1/0/5",  "GigabitEthernet1/0/6",
    "GigabitEthernet1/0/7",  "GigabitEthernet1/0/8",  "GigabitEthernet1/0/9",
    "GigabitEthernet1/0/10", "GigabitEthernet1/0/11", "GigabitEthernet1/0/12",
    "GigabitEthernet1/0/13", "GigabitEthernet1/0/14", "GigabitEthernet1/0/15",
    "GigabitEthernet1/0/16", "GigabitEthernet1/0/17", "GigabitEthernet1/0/18",
    "GigabitEthernet1/0/19", "GigabitEthernet1/0/20", "GigabitEthernet1/0/21",
    "GigabitEthernet1/0/22", "GigabitEthernet1/0/23", "GigabitEthernet1/0/24",
    "GigabitEthernet1/0/25", "GigabitEthernet1/0/26", "GigabitEthernet1/0/27",
    "GigabitEthernet1/0/28", "GigabitEthernet1/0/29", "GigabitEthernet1/0/30",
    "GigabitEthernet1/0/31", "GigabitEthernet1/0/32", "GigabitEthernet1/0/33",
    "GigabitEthernet1/0/34", "GigabitEthernet1/0/35", "GigabitEthernet1/0/36",
    "GigabitEthernet1/0/37", "GigabitEthernet1/0/38", "GigabitEthernet1/0/39",
    "GigabitEthernet1/0/40", "GigabitEthernet1/0/41", "GigabitEthernet1/0/42",
    "GigabitEthernet1/0/43", "GigabitEthernet1/0/44", "GigabitEthernet1/0/45",
    "GigabitEthernet1/0/46", "GigabitEthernet1/0/47", "GigabitEthernet1/0/48",
]

VLAN_DESCRIPTIONS = {
    range(1, 9):   ("VLAN10", "Servers"),
    range(9, 17):  ("VLAN20", "Workstations"),
    range(17, 25): ("VLAN30", "Printers"),
    range(25, 33): ("VLAN40", "VoIP"),
    range(33, 41): ("VLAN50", "Security Cameras"),
    range(41, 49): ("VLAN99", "Management"),
}

def get_vlan_for_port(port_num):
    for r, (vlan, desc) in VLAN_DESCRIPTIONS.items():
        if port_num in r:
            return vlan, desc
    return "VLAN1", "Default"

# Simulate: ~38 ports connected, 10 down
CONNECTED_PORTS = set(random.sample(range(1, 49), 38))

ports = {}
for i, name in enumerate(PORT_NAMES, start=1):
    connected = i in CONNECTED_PORTS
    vlan, vlan_desc = get_vlan_for_port(i)
    ports[i] = {
        "port_number": i,
        "name": name,
        "description": f"Port {i} - {vlan_desc}",
        "status": "connected" if connected else "notconnected",
        "admin_status": "up",
        "speed_mbps": random.choice([100, 1000]) if connected else 0,
        "duplex": "full" if connected else "unknown",
        "vlan": vlan,
        "vlan_description": vlan_desc,
        "mac_address": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)) if connected else None,
        # Cumulative byte counters (simulate realistic initial values)
        "bytes_in":  random.randint(10_000_000, 5_000_000_000) if connected else 0,
        "bytes_out": random.randint(10_000_000, 5_000_000_000) if connected else 0,
        "packets_in":  random.randint(10_000, 5_000_000) if connected else 0,
        "packets_out": random.randint(10_000, 5_000_000) if connected else 0,
        "errors_in":  random.randint(0, 50) if connected else 0,
        "errors_out": random.randint(0, 10) if connected else 0,
        "discards_in":  random.randint(0, 20) if connected else 0,
        "discards_out": random.randint(0, 5)  if connected else 0,
        # Rate tracking
        "_rate_bps_in":  random.randint(100_000, 50_000_000) if connected else 0,
        "_rate_bps_out": random.randint(100_000, 50_000_000) if connected else 0,
    }

# ── Background Traffic Simulation ────────────────────────────────────────────
def simulate_traffic():
    """Update port counters every second in background."""
    while True:
        time.sleep(1)
        for p in ports.values():
            if p["status"] == "connected":
                # Randomly vary rates ±10%
                factor_in  = random.uniform(0.90, 1.10)
                factor_out = random.uniform(0.90, 1.10)
                p["_rate_bps_in"]  = max(0, int(p["_rate_bps_in"]  * factor_in))
                p["_rate_bps_out"] = max(0, int(p["_rate_bps_out"] * factor_out))
                p["bytes_in"]  += p["_rate_bps_in"]  // 8
                p["bytes_out"] += p["_rate_bps_out"] // 8
                p["packets_in"]  += random.randint(10, 500)
                p["packets_out"] += random.randint(10, 500)
                if random.random() < 0.001:
                    p["errors_in"] += 1

traffic_thread = threading.Thread(target=simulate_traffic, daemon=True)
traffic_thread.start()

# ── Helpers ──────────────────────────────────────────────────────────────────
def uptime_seconds():
    return int(time.time() - BOOT_TIMESTAMP)

def format_uptime(seconds):
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return f"{d}d {h}h {m}m {s}s"

def public_port(p):
    """Strip internal _rate fields before returning."""
    return {k: v for k, v in p.items() if not k.startswith("_")}

# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "48-Port Network Switch Simulator API",
        "endpoints": {
            "GET /switch":          "Full switch snapshot (identity + all ports)",
            "GET /switch/info":     "Switch identity and uptime",
            "GET /switch/ports":    "All 48 ports with byte counters",
            "GET /switch/ports/<n>":"Single port detail (1–48)",
            "GET /switch/summary":  "Aggregated traffic summary across all ports",
            "POST /switch/reboot":  "Simulate switch reboot (resets uptime & counters)",
        }
    })


@app.route("/switch", methods=["GET"])
def get_switch():
    """Full switch snapshot – primary endpoint for Elastic Workflows."""
    uptime = uptime_seconds()
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "switch": {
            **SWITCH_INFO,
            "uptime_seconds": uptime,
            "uptime_human": format_uptime(uptime),
            "total_ports": 48,
            "ports_up":   sum(1 for p in ports.values() if p["status"] == "connected"),
            "ports_down": sum(1 for p in ports.values() if p["status"] != "connected"),
        },
        "ports": [public_port(p) for p in ports.values()],
    })


@app.route("/switch/info", methods=["GET"])
def get_switch_info():
    """Switch identity + uptime only."""
    uptime = uptime_seconds()
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **SWITCH_INFO,
        "uptime_seconds": uptime,
        "uptime_human": format_uptime(uptime),
    })


@app.route("/switch/ports", methods=["GET"])
def get_ports():
    """All 48 ports."""
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_ports": 48,
        "ports": [public_port(p) for p in ports.values()],
    })


@app.route("/switch/ports/<int:port_num>", methods=["GET"])
def get_port(port_num):
    """Single port detail."""
    if port_num not in ports:
        return jsonify({"error": f"Port {port_num} not found. Valid range: 1–48"}), 404
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **public_port(ports[port_num]),
    })


@app.route("/switch/summary", methods=["GET"])
def get_summary():
    """Aggregated traffic across all ports."""
    total_in  = sum(p["bytes_in"]  for p in ports.values())
    total_out = sum(p["bytes_out"] for p in ports.values())
    total_pkt_in  = sum(p["packets_in"]  for p in ports.values())
    total_pkt_out = sum(p["packets_out"] for p in ports.values())
    total_err_in  = sum(p["errors_in"]   for p in ports.values())
    total_err_out = sum(p["errors_out"]  for p in ports.values())
    uptime = uptime_seconds()
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "switch_name": SWITCH_INFO["name"],
        "serial_number": SWITCH_INFO["serial_number"],
        "vendor": SWITCH_INFO["vendor"],
        "model": SWITCH_INFO["model"],
        "software_version": SWITCH_INFO["software_version"],
        "uptime_seconds": uptime,
        "uptime_human": format_uptime(uptime),
        "total_bytes_in":    total_in,
        "total_bytes_out":   total_out,
        "total_bytes":       total_in + total_out,
        "total_packets_in":  total_pkt_in,
        "total_packets_out": total_pkt_out,
        "total_errors_in":   total_err_in,
        "total_errors_out":  total_err_out,
        "ports_up":   sum(1 for p in ports.values() if p["status"] == "connected"),
        "ports_down": sum(1 for p in ports.values() if p["status"] != "connected"),
    })


@app.route("/switch/reboot", methods=["POST"])
def reboot():
    """Simulate a switch reboot – resets uptime and counters."""
    global BOOT_TIMESTAMP
    BOOT_TIMESTAMP = time.time()
    SWITCH_INFO["boot_time"] = datetime.now(timezone.utc).isoformat()
    for p in ports.values():
        if p["status"] == "connected":
            p["bytes_in"] = p["bytes_out"] = 0
            p["packets_in"] = p["packets_out"] = 0
            p["errors_in"] = p["errors_out"] = 0
            p["discards_in"] = p["discards_out"] = 0
    return jsonify({
        "message": "Switch rebooted successfully",
        "boot_time": SWITCH_INFO["boot_time"],
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  48-Port Network Switch Simulator")
    print(f"  Device : {SWITCH_INFO['vendor']} {SWITCH_INFO['model']}")
    print(f"  Serial : {SWITCH_INFO['serial_number']}")
    print(f"  Version: {SWITCH_INFO['software_version']}")
    print("=" * 60)
    print("  Endpoints:")
    print("    GET  http://0.0.0.0:8081/switch")
    print("    GET  http://0.0.0.0:8081/switch/info")
    print("    GET  http://0.0.0.0:8081/switch/ports")
    print("    GET  http://0.0.0.0:8081/switch/ports/<1-48>")
    print("    GET  http://0.0.0.0:8081/switch/summary")
    print("    POST http://0.0.0.0:8081/switch/reboot")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8081, debug=False)
