# Skimmer Sentinel: Credit Card Skimmer Detection & Mapping Framework

### Professional-grade hardware detection system for identifying and mapping Bluetooth-based credit card skimmers at fuel stations.

## Overview

Skimmer Sentinel is a comprehensive hardware-focused framework designed to detect, document, and map Bluetooth-based credit card skimmers commonly deployed at fuel pumps. Built for community safety initiatives and law enforcement collaboration, this tool provides professional-grade threat assessment and evidence collection capabilities.

 The Problem

Credit card skimmers are increasingly sophisticated devices that criminals install on fuel pumps and ATMs. These Bluetooth-enabled devices can:

· Transmit stolen card data wirelessly to criminals in nearby vehicles
· Operate for weeks without detection
· Steal thousands of card numbers before discovery
· Cost victims and businesses millions annually

 The Solution

Skimmer Sentinel transforms community safety efforts with:

· Hardware Detection: Aggressive Bluetooth scanning for known skimmer signatures
· Evidence Chain: Court-admissible documentation with timestamps and GPS
· Threat Mapping: Interactive heatmaps showing skimmer hotspots
· Law Enforcement Reports: Professionally formatted packages for police
· Community Coordination: Patrol management and station monitoring

## Features

 Detection Engine

· Bluetooth Signature Analysis: Identifies HC-05, HC-06, Linvor, and other common skimmer modules
· RSSI-Based Proximity Detection: Strong signal detection indicates close-range threats
· Service UUID Matching: Detects Serial Port Profile (SPP) and custom skimmer services
· Threat Scoring: 1-10 threat level based on multiple detection factors

 Visualization & Mapping

· Interactive Folium Maps: GPS-based threat visualization with cluster markers
· Heatmap Overlays: Identify high-density skimmer activity zones
· Printable Reports: HTML/PDF reports perfect for police briefings
· Historical Timeline: Animated timeline showing skimmer activity over time

 Evidence Management

· SQLite Database: Tamper-evident evidence chain with full audit trail
· Visual Documentation: Support for photo evidence collection
· Station Risk Scoring: Track repeat offenders and high-risk locations
· Export Functions: Generate law enforcement-ready evidence packages

 Operational Modes

· RECON: Quick station assessment (5-10 minutes)
· PATROL: Systematic multi-station inspection routes
· WARDIRVING: Continuous mobile scanning while driving
· STATION SWEEP: Organized community patrols

---

# Installation


### 1. Clone the repository

```bash
git clone https://github.com/ekomsSavior/SkimmerSentinel.git
cd SkimmerSentinel
```

### 2. Install Dependencies

```bash
sudo apt update && sudo apt install -y python3-pip bluez bluetooth python3-tk git
```
```bash
sudo pip3 install bleak folium geopy pandas pillow bleak --break-system-packages
```
### 3. Initialize Database

```bash
# Initialize database
echo "[*] Creating evidence database..."
sqlite3 data/detections.db "VACUUM;"

# Create town station file
echo '[
  {"name": "Shell Main St", "address": "123 Main St", "priority": 1},
  {"name": "76 Highway", "address": "456 Highway 99", "priority": 2},
  {"name": "Costco Gas", "address": "789 Retail Way", "priority": 3}
]' > data/town_stations.json

# Set permissions
chmod +x sentinel.py

echo "[+] Setup complete."
```
## Hardware Verification
 
Bring the adapter UP
```bash
sudo hciconfig hci0 up   #or hci1 
```

Check your bluetooth adapter is working
```bash
sudo hciconfig -a
```

Test Bluetooth
```bash
sudo hcitool scan
```
 Quick Start Guide

First-Time Deployment

```bash
# 1. Launch as root (Bluetooth requires elevated privileges)
sudo python3 sentinel.py

# 2. Initial system check should show:
# ======================================================================
# SKIMMER SENTINEL INITIALIZING
# ======================================================================
# [*] Hardware check...
# [*] Loading modules...
# [*] Database connected...
# [+] READY FOR DEPLOYMENT
# [*] Bleak scanner initialized for hci0
# [+] Adapter hci0 ready

# 3. You'll see the main menu:
# ======================================================================
# SKIMMER SENTINEL - MISSION CONTROL
# ======================================================================
# 1. RECON: Scan current location
# 2. PATROL: Systematic station inspection
# 3. WARDRIVE: Continuous mobile scanning
# 4. EVIDENCE: View collected data
# 5. MAP: Generate threat visualization
# 6. REPORT: Create law enforcement package
# 7. DEPLOY: Countermeasures (read-only)
# 8. EXIT
```
---

Your First Skimmer Scan

```bash
# From the main menu, choose option 1 (RECON)

[+] RECON MODE - Quick Threat Assessment
[?] Station name: Shell Main Street
[?] Address: 123 Main Street, Your Town
[*] Scanning Shell Main Street...

# Expected outcomes:
# 1. CLEAN SCAN: "[+] No immediate threats detected"
# 2. THREAT DETECTED: 
#    [!] THREAT DETECTED: 2 suspicious device(s)
#        1. HC-05 (RSSI: -45) - Threat: 8/10
#        2. Linvor (RSSI: -60) - Threat: 7/10
#    [+] Evidence logged: DET-20250101120000
```

Building Your Patrol Route

```bash
# 1. Choose option 2 (PATROL)
# 2. When prompted, create new patrol route
# 3. Add stations in your town:
#    Station name: Shell Main Street
#    Address: 123 Main Street
#    Station name: 76 Highway
#    Address: 456 Highway 99
#    Station name: done

# 4. Systematically visit each station
# 5. Press Enter at each location to scan
# 6. Evidence automatically saved to database
```

---

## Operational Modes

- RECON Mode (Option 1)

Purpose: Quick assessment of a single location
Time Required: 2-3 minutes per station
Best For:

· Suspected skimmer locations
· High-risk stations
· Quick verification
  Output: Immediate threat assessment, evidence saved to DB

- PATROL Mode (Option 2)

Purpose: Systematic town-wide inspection
Time Required: 30-60 minutes for 5-10 stations
Best For:

· Weekly community patrols
· Law enforcement sweeps
· Corporate security checks
  Output: Comprehensive town threat profile, risk scoring

- WARDIRVING Mode (Option 3)

Purpose: Continuous mobile scanning
Time Required: Variable (drive-time dependent)
Best For:

· Mapping entire cities
· Identifying skimmer corridors
· Highway route monitoring
  Output: Heatmaps, hotspot identification, temporal analysis

- EVIDENCE Mode (Option 4)

Purpose: Review collected data
Features:

· View last 20 detections
· Threat statistics
· Station risk scores
· Evidence chain verification

- MAP Mode (Option 5)

Purpose: Threat visualization
Features:

· Interactive Folium maps (requires folium)
· Heatmap overlays
· Cluster visualization
· Printable HTML reports
· Police briefing packages

- REPORT Mode (Option 6)

Purpose: Law enforcement collaboration
Features:

· Professional report formatting
· Executive summaries
· Affected station lists
· Recommended actions
· Contact information templates

- COUNTERMEASURES Mode (Option 7)

Purpose: Defensive information
Features:

· Legal guidance
· Deterrent strategies
· Community education
· Security best practices

---

## Technical Specifications

Skimmer Detection Signatures

```python
# Hardware signatures (core/scanner.py)
skimmer_signatures = [
    "HC-05", "HC-06", "Linvor", "RNBT", 
    "BT05", "BT06", "JDY-31", "SPP",
    "SerialPort", "BT-SPP", "MLT-BT05",
    "DSD-TECH", "JDY-31", "BT-SERIAL"
]

# Bluetooth service UUIDs
skimmer_services = {
    "00001101-0000-1000-8000-00805f9b34fb",  # Serial Port Profile (SPP)
    "0000ffe0-0000-1000-8000-00805f9b34fb",  # HC-05 custom service
    "0000ffe0-0000-1000-8000-00805f9b34fb",  # Some clones
}
```

Threat Scoring Algorithm

```python
# Threat levels 1-10 based on:
# 1. Device name match: +7 points (HC-05/HC-06)
# 2. Signal strength: 
#    - >-50 dBm: +3 points (very close)
#    - >-70 dBm: +1 point (nearby)
# 3. Service UUID match: +2 points
# 4. Very strong signal (>-30 dBm): +2 points
# Max score: 10 (Critical Threat)
```

⚖️ Legal Disclaimer

IMPORTANT: Skimmer Sentinel is designed for DEFENSIVE and EVIDENCE COLLECTION purposes only.

1. Document from a safe distance
2. Never touch suspected skimmers
3. Notify station management
4. Contact police with evidence
5. Follow official investigation procedures
------------

Software Updates

```bash
# Update from repository
git pull origin main

```

 Troubleshooting

Common Issues

Bluetooth Adapter Not Found

```bash
# Check adapter status
sudo hciconfig -a

# If no adapters shown:
sudo modprobe btusb
sudo systemctl restart bluetooth
sudo hciconfig hci0 up
```

Permission Denied Errors

```bash
# Ensure you're running as root
sudo python3 sentinel.py

# Check Bluetooth permissions
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python3))
```

Missing Dependencies

```bash
# Reinstall all dependencies
sudo pip3 install --force-reinstall --break-system-packages \
    bleak folium pandas numpy pillow geopy
```

Database Errors

```bash
# Backup and recreate database
mv data/detections.db data/detections_corrupt.db
sqlite3 data/detections.db "VACUUM;"
```

Performance Tuning

```bash
# Increase Bluetooth scan range
sudo hciconfig hci0 txpower 12  # Max power (12 dBm)

# Reduce scan interval for wardriving
# In sentinel.py, adjust: scan_interval=10 (seconds)

# Increase database cache
echo "PRAGMA cache_size = 10000;" | sqlite3 data/detections.db
```

