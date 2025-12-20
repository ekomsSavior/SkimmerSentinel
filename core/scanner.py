import asyncio
import subprocess
import time
from datetime import datetime
from collections import deque

class HardwareScanner:
    def __init__(self, adapter="hci0"):
        self.adapter = adapter
        self.skimmer_signatures = [
            "HC-05", "HC-06", "Linvor", "RNBT", 
            "BT05", "BT06", "JDY-31", "SPP",
            "SerialPort", "BT-SPP", "MLT-BT05",
            "DSD-TECH", "JDY-31", "BT-SERIAL"
        ]
        
        # Common skimmer service UUIDs
        self.skimmer_services = {
            "00001101-0000-1000-8000-00805f9b34fb",  # Serial Port Profile (SPP)
            "0000ffe0-0000-1000-8000-00805f9b34fb",  # HC-05 custom service
            "0000ffe0-0000-1000-8000-00805f9b34fb",  # Some clones
        }
        
        # Wardriving tracking
        self.continuous_scanning = False
        self.detection_history = deque(maxlen=1000)  # Last 1000 detections
        self.hotspot_history = {}  # Station -> detection count
        
        # Try to import bleak with fallback
        self.bleak_available = False
        try:
            from bleak import BleakScanner
            self.BleakScanner = BleakScanner
            self.bleak_available = True
            print(f"[*] Bleak scanner initialized for {adapter}")
        except ImportError:
            print("[!] Bleak not available, will use hcitool fallback")
    
    def start_bluetooth_service(self):
        """Ensure Bluetooth service is running"""
        try:
            # Try systemctl first
            result = subprocess.run(
                ["sudo", "systemctl", "start", "bluetooth"],
                capture_output=True,
                text=True
            )
            
            # Check if service is running
            check = subprocess.run(
                ["systemctl", "is-active", "bluetooth"],
                capture_output=True,
                text=True
            )
            
            if "active" in check.stdout:
                print("[+] Bluetooth service started")
                return True
            else:
                # Try direct service command
                subprocess.run(["sudo", "service", "bluetooth", "start"], 
                             capture_output=True)
                time.sleep(2)
                return True
                
        except Exception as e:
            print(f"[!] Failed to start Bluetooth: {e}")
            return False
    
    def check_adapter(self):
        """Verify Bluetooth adapter is operational"""
        # First ensure service is running
        if not self._check_bluetooth_service():
            print("[!] Bluetooth service not running, attempting to start...")
            if not self.start_bluetooth_service():
                return False
        
        try:
            # Bring adapter up
            subprocess.run(["sudo", "hciconfig", self.adapter, "up"], 
                         capture_output=True)
            
            # Set to piscan mode
            subprocess.run(["sudo", "hciconfig", self.adapter, "piscan"], 
                         capture_output=True)
            
            # Verify
            result = subprocess.run(
                ["hciconfig", self.adapter],
                capture_output=True,
                text=True
            )
            
            if "UP" in result.stdout and "RUNNING" in result.stdout:
                print(f"[+] Adapter {self.adapter} ready")
                return True
            else:
                print(f"[!] Adapter {self.adapter} not ready")
                return False
                
        except Exception as e:
            print(f"[!] Could not check adapter {self.adapter}: {e}")
            return False
    
    def _check_bluetooth_service(self):
        """Check if Bluetooth service is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "bluetooth"],
                capture_output=True,
                text=True
            )
            return "active" in result.stdout
        except:
            try:
                # Alternative check
                result = subprocess.run(
                    ["service", "bluetooth", "status"],
                    capture_output=True,
                    text=True
                )
                return "running" in result.stdout.lower()
            except:
                return False
    
    async def aggressive_scan(self, duration=30):
        """Comprehensive Bluetooth scan for skimmer patterns"""
        print(f"[*] Starting aggressive scan on {self.adapter} ({duration}s)...")
        
        if not self.check_adapter():
            print("[!] Adapter check failed, attempting recovery...")
            self.start_bluetooth_service()
            time.sleep(3)
        
        if self.bleak_available:
            return await self._bleak_scan(duration)
        else:
            return await self._hcitool_scan(duration)
    
    async def _bleak_scan(self, duration):
        """Scan using Bleak library"""
        try:
            devices = await self.BleakScanner.discover(
                timeout=duration,
                adapter=self.adapter,
                return_adv=True
            )
            
            suspicious = []
            for addr, (dev, adv) in devices.items():
                device_info = self._create_device_info(
                    addr=addr,
                    name=dev.name or "Unknown",
                    rssi=adv.rssi if adv.rssi else -100,
                    services=list(adv.service_uuids) if adv.service_uuids else []
                )
                
                if self._is_suspicious(device_info):
                    device_info["threat_level"] = self._assess_threat(device_info)
                    suspicious.append(device_info)
                    
                    # Log immediately
                    self._log_finding(device_info)
                    
                    # Add to history for wardriving tracking
                    self._add_to_history(device_info)
            
            print(f"[*] Bleak scan complete: {len(suspicious)} suspicious device(s)")
            return suspicious
            
        except Exception as e:
            print(f"[!] Bleak scan failed: {e}")
            # Fallback to hcitool
            return await self._hcitool_scan(duration)
    
    async def _hcitool_scan(self, duration):
        """Fallback scan using hcitool"""
        try:
            # Ensure adapter is ready
            subprocess.run(["sudo", "hciconfig", self.adapter, "piscan"], 
                         capture_output=True)
            
            # Run scan
            result = subprocess.run(
                ["timeout", str(duration), "hcitool", "scan"],
                capture_output=True,
                text=True
            )
            
            suspicious = []
            for line in result.stdout.split('\n')[1:]:
                line = line.strip()
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        addr = parts[0].strip()
                        name = parts[1].strip()
                        
                        device_info = self._create_device_info(
                            addr=addr,
                            name=name,
                            rssi=-70,  # Default RSSI for hcitool
                            services=[]
                        )
                        
                        if self._is_suspicious(device_info):
                            device_info["threat_level"] = self._assess_threat(device_info)
                            suspicious.append(device_info)
                            
                            # Log immediately
                            self._log_finding(device_info)
                            
                            # Add to history for wardriving tracking
                            self._add_to_history(device_info)
            
            print(f"[*] hcitool scan complete: {len(suspicious)} suspicious device(s)")
            return suspicious
            
        except Exception as e:
            print(f"[!] hcitool scan failed: {e}")
            return []
    
    def _create_device_info(self, addr, name, rssi, services):
        """Create standardized device info dict"""
        return {
            "address": addr,
            "name": name,
            "rssi": rssi,
            "timestamp": datetime.now().isoformat(),
            "services": services,
            "location": None,  # Will be populated by wardriving mode
            "gps_coords": None
        }
    
    def _is_suspicious(self, device):
        """Heuristic detection of skimmer devices"""
        name = str(device["name"]).upper()
        
        # Pattern matching in device names
        for sig in self.skimmer_signatures:
            if sig.upper() in name:
                return True
        
        # Behavioral indicators - strong signal (possibly hidden nearby)
        if device["rssi"] > -40:
            return True
        
        # Service UUID matching (only works with Bleak)
        if device["services"]:
            if any(svc in self.skimmer_services for svc in device["services"]):
                return True
        
        # Generic serial/BT device names often used for skimmers
        generic_suspicious = ["SERIAL", "PORT", "COM", "BT_", "BLUETOOTH", "HC-"]
        for generic in generic_suspicious:
            if generic in name and len(name) < 20:  # Short generic names
                return True
        
        return False
    
    def _assess_threat(self, device):
        """Assign threat level 1-10"""
        score = 0
        
        name = str(device["name"])
        
        # Name match (high confidence)
        if any(sig in name for sig in ["HC-05", "HC-06"]):
            score += 7
        
        # Signal strength (closer = higher threat)
        rssi = device["rssi"]
        if rssi > -50:
            score += 3
        elif rssi > -70:
            score += 1
        
        # Service UUID match
        if device["services"]:
            score += 2
        
        # Very strong signal (likely very close)
        if rssi > -30:
            score += 2
        
        return min(score, 10)
    
    def _log_finding(self, device):
        """Immediate logging for evidence chain"""
        try:
            with open("logs/skimmer_log.txt", "a") as f:
                f.write(f"[{device['timestamp']}] THREAT_LEVEL_{device['threat_level']}: "
                       f"{device['name']} ({device['address']}) RSSI:{device['rssi']}\n")
        except Exception as e:
            print(f"[!] Failed to log finding: {e}")
    
    def _add_to_history(self, device):
        """Add detection to history for wardriving analysis"""
        self.detection_history.append(device)
        
        # Track by address
        addr = device["address"]
        if addr not in self.hotspot_history:
            self.hotspot_history[addr] = {
                "first_seen": device["timestamp"],
                "last_seen": device["timestamp"],
                "count": 1,
                "max_threat": device["threat_level"],
                "locations": []
            }
        else:
            self.hotspot_history[addr]["count"] += 1
            self.hotspot_history[addr]["last_seen"] = device["timestamp"]
            self.hotspot_history[addr]["max_threat"] = max(
                self.hotspot_history[addr]["max_threat"],
                device["threat_level"]
            )
    
    # ===== WARDIRVING MODE METHODS =====
    
    async def continuous_wardrive(self, scan_interval=10, location_callback=None):
        """
        Continuous scanning mode for wardriving
        scan_interval: seconds between scans
        location_callback: function to call with current location (lat, lon)
        """
        print(f"\n[+] STARTING WARDIRVING MODE (interval: {scan_interval}s)")
        print("[+] Press Ctrl+C to stop and generate heatmap")
        
        self.continuous_scanning = True
        scan_count = 0
        
        try:
            while self.continuous_scanning:
                scan_count += 1
                print(f"\n[*] Wardrive scan #{scan_count} at {datetime.now().strftime('%H:%M:%S')}")
                
                # Get current location if callback provided
                current_location = None
                if location_callback:
                    try:
                        current_location = location_callback()
                        print(f"[*] Location: {current_location}")
                    except Exception as e:
                        print(f"[!] Location error: {e}")
                
                # Perform scan
                devices = await self.aggressive_scan(duration=scan_interval-2)
                
                # Enhance devices with location data
                for device in devices:
                    device["location"] = current_location
                    if current_location:
                        device["gps_coords"] = current_location
                
                if devices:
                    print(f"[!] {len(devices)} skimmer(s) detected this scan")
                    
                    # Save batch to database
                    self._save_wardrive_batch(devices, scan_count)
                
                # Brief pause before next scan
                await asyncio.sleep(2)
                
        except KeyboardInterrupt:
            print("\n[+] Wardriving stopped by user")
        except Exception as e:
            print(f"[!] Wardriving error: {e}")
        finally:
            self.continuous_scanning = False
            self._generate_wardrive_report(scan_count)
    
    def _save_wardrive_batch(self, devices, scan_batch_id):
        """Save wardriving batch to database"""
        try:
            import json
            from datetime import datetime
            
            batch_data = {
                "batch_id": f"WARDRIBE_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{scan_batch_id}",
                "timestamp": datetime.now().isoformat(),
                "device_count": len(devices),
                "devices": devices
            }
            
            # Save to logs directory
            with open(f"logs/wardrive_batch_{scan_batch_id}.json", "w") as f:
                json.dump(batch_data, f, indent=2)
            
            print(f"[+] Wardrive batch {scan_batch_id} saved")
            
        except Exception as e:
            print(f"[!] Failed to save wardrive batch: {e}")
    
    def _generate_wardrive_report(self, total_scans):
        """Generate wardriving summary report"""
        try:
            from datetime import datetime
            
            report = {
                "report_id": f"WARDRIBE_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "generated": datetime.now().isoformat(),
                "total_scans": total_scans,
                "total_detections": len(self.detection_history),
                "unique_devices": len(self.hotspot_history),
                "hotspots": []
            }
            
            # Identify top hotspots
            sorted_hotspots = sorted(
                self.hotspot_history.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )[:10]  # Top 10
            
            for addr, data in sorted_hotspots:
                report["hotspots"].append({
                    "address": addr,
                    "detection_count": data["count"],
                    "max_threat": data["max_threat"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"]
                })
            
            # Save report
            report_file = f"exports/wardrive_report_{datetime.now().strftime('%Y%m%d')}.json"
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2)
            
            print(f"\n[+] Wardrive report generated: {report_file}")
            print(f"    Total scans: {total_scans}")
            print(f"    Total detections: {len(self.detection_history)}")
            print(f"    Unique skimmers: {len(self.hotspot_history)}")
            
            if sorted_hotspots:
                print("\n[+] TOP SKIMMER HOTSPOTS:")
                for i, (addr, data) in enumerate(sorted_hotspots[:5], 1):
                    print(f"    {i}. {addr[:17]}... - {data['count']} hits (Threat: {data['max_threat']}/10)")
            
        except Exception as e:
            print(f"[!] Failed to generate wardrive report: {e}")
    
    def get_wardrive_stats(self):
        """Get current wardriving statistics"""
        return {
            "continuous_scanning": self.continuous_scanning,
            "total_detections": len(self.detection_history),
            "unique_devices": len(self.hotspot_history),
            "recent_detections": list(self.detection_history)[-10:] if self.detection_history else []
        }
