# SkimmerSentinel
credit card skimmer mapping framework


## Installation


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
pip3 install bleak folium geopy pandas pillow bleak --break-system-packages
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
