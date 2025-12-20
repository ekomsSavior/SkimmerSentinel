#!/usr/bin/env python3
"""
SKIMMER SENTINEL
hardware-focused skimmer detection
"""

import sys
import json
import sqlite3
from datetime import datetime
import asyncio
from core.scanner import HardwareScanner
from core.evidence import EvidenceCollector
from core.reporter import LawEnforcementReport

# Try to import mapper, but handle missing folium gracefully
try:
    from core.mapper import ThreatMapper
    MAPPER_AVAILABLE = True
except ImportError as e:
    if "folium" in str(e):
        print("[!] Folium library not installed. Map features will be limited.")
        print("[*] Install it with: pip3 install folium pandas numpy")
        MAPPER_AVAILABLE = False
    else:
        raise

class Sentinel:
    def __init__(self):
        self.scanner = HardwareScanner(adapter="hci0")  
        self.evidence = EvidenceCollector()
        self.reporter = LawEnforcementReport()
        self.current_mission = None
        
        # Initialize mapper only if available
        if MAPPER_AVAILABLE:
            self.mapper = ThreatMapper()
        else:
            self.mapper = None
        
        # Verify hardware
        if not self.scanner.check_adapter():
            print("[!] Bluetooth adapter not found!")
            print("[*] Check: hciconfig -a")
            sys.exit(1)
        
        self.setup_database()
    
    def setup_database(self):
        """Evidence database"""
        self.conn = sqlite3.connect('data/detections.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                timestamp DATETIME,
                station_name TEXT,
                station_address TEXT,
                gps_coords TEXT,
                pump_number TEXT,
                threat_level INTEGER,
                bluetooth_devices TEXT,
                visual_evidence TEXT,
                notes TEXT,
                reporter TEXT DEFAULT 'Sentinel_Operator'
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS stations (
                id TEXT PRIMARY KEY,
                name TEXT,
                address TEXT,
                last_checked DATETIME,
                total_detections INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0
            )
        ''')
        
        self.conn.commit()
    
    def mission_control(self):
        """Main interactive menu"""
        while True:
            print("\n" + "="*70)
            print("SKIMMER SENTINEL - MISSION CONTROL")
            print("="*70)
            print("1. RECON: Scan current location")
            print("2. PATROL: Systematic station inspection")
            print("3. WARDRIVE: Continuous mobile scanning")
            print("4. EVIDENCE: View collected data")
            print("5. MAP: Generate threat visualization")
            print("6. REPORT: Create law enforcement package")
            print("7. DEPLOY: Countermeasures (read-only)")
            print("8. EXIT")
            print("="*70)
            
            choice = input("\n[+] SELECT OPERATION: ").strip()
            
            if choice == "1":
                self.recon_scan()
            elif choice == "2":
                self.patrol_mode()
            elif choice == "3":
                self.wardriving_mode()
            elif choice == "4":
                self.view_evidence()
            elif choice == "5":
                self.generate_threat_map()
            elif choice == "6":
                self.create_authority_report()
            elif choice == "7":
                self.deploy_countermeasures()
            elif choice == "8":
                print("\n[+] Mission logged. Stay vigilant.\n")
                sys.exit(0)
            else:
                print("[!] Invalid selection")
    
    def recon_scan(self):
        """Quick scan of current location"""
        print("\n[+] RECON MODE - Quick Threat Assessment")
        
        # Get location
        station_name = input("[?] Station name: ").strip() or "UNKNOWN"
        address = input("[?] Address: ").strip() or "UNKNOWN"
        
        # Run scan
        print(f"[*] Scanning {station_name}...")
        
        try:
            # Async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            devices = loop.run_until_complete(
                self.scanner.aggressive_scan(duration=15)
            )
            
            if devices:
                print(f"\n[!] THREAT DETECTED: {len(devices)} suspicious device(s)")
                for i, dev in enumerate(devices, 1):
                    print(f"    {i}. {dev['name']} (RSSI: {dev['rssi']}) - Threat: {dev['threat_level']}/10")
                
                # Save to database
                detection_id = f"DET-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                self.cursor.execute('''
                    INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    detection_id,
                    datetime.now().isoformat(),
                    station_name,
                    address,
                    "GPS_COORDS_HERE",  # Add GPS module if available
                    "UNKNOWN",
                    max(d.get('threat_level', 0) for d in devices),
                    json.dumps(devices),
                    "{}",
                    "Recon scan detection",
                    "Sentinel_Operator"
                ))
                self.conn.commit()
                
                print(f"[+] Evidence logged: {detection_id}")
                
                # Immediate action recommendation
                self._recommend_action(devices, station_name)
            else:
                print("[+] No immediate threats detected")
                
        except Exception as e:
            print(f"[!] Scan failed: {e}")
    
    def wardriving_mode(self):
        """Continuous wardriving mode for mobile scanning"""
        print("\n" + "="*70)
        print("WARDIRVING MODE - Mobile Continuous Scanning")
        print("="*70)
        print("\n[+] This mode continuously scans while you drive")
        print("[+] Perfect for scanning entire towns or routes")
        print("[+] Press Ctrl+C at any time to stop")
        
        # Get scan interval
        interval = input("\n[?] Scan interval in seconds (default: 15): ").strip()
        interval = int(interval) if interval.isdigit() else 15
        
        # Optional: GPS integration
        use_gps = input("[?] Use GPS for location tracking? (y/n): ").lower() == 'y'
        
        # Define location callback (simulated or real GPS)
        location_callback = None
        if use_gps:
            try:
                # Try to import GPS module
                import gpsd
                gpsd.connect()
                location_callback = lambda: (gpsd.get_current().lat, gpsd.get_current().lon)
                print("[+] GPS connected")
            except ImportError:
                print("[!] Install gpsd for GPS tracking: sudo apt install gpsd gpsd-clients")
                print("[*] Using simulated location tracking")
                # Simulated location callback
                location_callback = lambda: (47.6062, -122.3321)  # Default coordinates
        
        print(f"\n[+] Starting wardriving with {interval}s intervals...")
        print("[+] Driving and scanning...\n")
        
        try:
            # Run continuous wardriving
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                self.scanner.continuous_wardrive(
                    scan_interval=interval,
                    location_callback=location_callback
                )
            )
            
        except KeyboardInterrupt:
            print("\n[+] Wardriving stopped")
        except Exception as e:
            print(f"[!] Wardriving error: {e}")
    
    def _recommend_action(self, devices, station_name):
        """Immediate response protocol"""
        max_threat = max(d.get('threat_level', 0) for d in devices)
        
        if max_threat >= 8:
            print("\n[!] IMMEDIATE ACTION REQUIRED:")
            print("    1. NOTIFY station management")
            print("    2. CALL police non-emergency")
            print("    3. WARN customers (discreetly)")
            print("    4. DOCUMENT with photos (from distance)")
        
        elif max_threat >= 5:
            print("\n[!] INVESTIGATION RECOMMENDED:")
            print(f"    Station: {station_name}")
            print(f"    Threat level: {max_threat}/10")
            print("    Consider notifying authorities")
    
    def patrol_mode(self):
        """Systematic inspection of multiple stations"""
        print("\n" + "="*70)
        print("PATROL MODE - Systematic Town Sweep")
        print("="*70)
        
        # Load town stations
        stations = self._load_town_stations()
        
        if not stations:
            print("[*] No stations loaded. Creating new patrol route...")
            stations = self._create_patrol_route()
        
        for i, station in enumerate(stations, 1):
            print(f"\n[{i}/{len(stations)}] Target: {station['name']}")
            print(f"    Address: {station['address']}")
            
            input("[*] Press Enter when in position (or 's' to skip)... ")
            
            # Scan this location
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                devices = loop.run_until_complete(
                    self.scanner.aggressive_scan(duration=20)
                )
                
                if devices:
                    print(f"[!] {len(devices)} threat(s) detected!")
                    # Collect visual evidence
                    evidence = self.evidence.collect_visual(station)
                    # Save to database
                    self._save_patrol_finding(station, devices, evidence)
                else:
                    print("[+] Clean scan")
                    
            except KeyboardInterrupt:
                print("[*] Patrol interrupted")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
        
        print("\n[+] Patrol complete. Review evidence in database.")
    
    def _load_town_stations(self):
        """Load known gas stations in your town"""
        try:
            with open('data/town_stations.json', 'r') as f:
                return json.load(f)
        except:
            return []
    
    def _create_patrol_route(self):
        """Interactive patrol route creation"""
        print("\n[*] Creating new patrol route for your town")
        stations = []
        
        while True:
            print("\n--- Add Station ---")
            name = input("Station name (or 'done'): ").strip()
            if name.lower() == 'done':
                break
            
            address = input("Address: ").strip()
            
            stations.append({
                "name": name,
                "address": address,
                "priority": len(stations) + 1
            })
            
            print(f"[+] Added {name}")
        
        # Save for future patrols
        with open('data/town_stations.json', 'w') as f:
            json.dump(stations, f, indent=2)
        
        return stations
    
    def _save_patrol_finding(self, station, devices, evidence):
        """Save patrol findings with full evidence chain"""
        detection_id = f"PATROL-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.cursor.execute('''
            INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection_id,
            datetime.now().isoformat(),
            station['name'],
            station['address'],
            "GPS_PENDING",
            "ALL_PUMPS",
            max(d.get('threat_level', 0) for d in devices),
            json.dumps(devices),
            json.dumps(evidence),
            f"Patrol finding at {station['name']}",
            "Sentinel_Patrol"
        ))
        
        # Update station risk score
        self.cursor.execute('''
            INSERT OR REPLACE INTO stations (id, name, address, last_checked, total_detections, risk_score)
            VALUES (?, ?, ?, ?, COALESCE((SELECT total_detections FROM stations WHERE id = ?), 0) + 1, 
                    COALESCE((SELECT risk_score FROM stations WHERE id = ?), 0) + ?)
        ''', (
            station['name'],
            station['name'],
            station['address'],
            datetime.now().isoformat(),
            station['name'],
            station['name'],
            len(devices) * 2
        ))
        
        self.conn.commit()
        print(f"[+] Evidence saved: {detection_id}")
    
    def view_evidence(self):
        """Review collected evidence"""
        print("\n" + "="*70)
        print("EVIDENCE DATABASE")
        print("="*70)
        
        self.cursor.execute('''
            SELECT id, timestamp, station_name, threat_level, notes 
            FROM detections 
            ORDER BY timestamp DESC 
            LIMIT 20
        ''')
        
        findings = self.cursor.fetchall()
        
        if not findings:
            print("[*] No evidence collected yet")
            return
        
        for fid, timestamp, station, threat, notes in findings:
            print(f"\nID: {fid}")
            print(f"  Station: {station}")
            print(f"  Time: {timestamp[:19]}")
            print(f"  Threat: {threat}/10")
            print(f"  Notes: {notes[:60]}...")
        
        # Statistics
        self.cursor.execute('SELECT COUNT(*), AVG(threat_level) FROM detections')
        count, avg_threat = self.cursor.fetchone()
        print(f"\n[*] Total detections: {count}")
        print(f"[*] Average threat level: {avg_threat:.1f}/10")
    
    def generate_threat_map(self):
        """Create visualization of threats in town"""
        print("\n" + "="*70)
        print("GENERATING THREAT MAP")
        print("="*70)
        
        if not MAPPER_AVAILABLE or self.mapper is None:
            print("[!] Advanced mapping features require folium")
            print("[*] Install dependencies: pip3 install folium pandas numpy")
            print("[*] For now, using basic text-based map...")
            self._generate_text_map()
            return
        
        # Use the new mapper if available
        try:
            map_file = self.mapper.generate_map()
            
            if map_file and map_file != "No data available for mapping":
                print(f"\n[✓] Interactive map generated successfully!")
                print(f"[*] File saved: {map_file}")
                print("[*] Open it in your web browser to view")
                print("[*] Perfect for police presentations!")
            else:
                print("[!] Could not generate map")
                print("[*] Using fallback method...")
                self._generate_text_map()
                
        except Exception as e:
            print(f"[!] Map generation failed: {e}")
            print("[*] Using fallback method...")
            self._generate_text_map()
    
    def _generate_text_map(self):
        """Generate simple text-based threat map"""
        print("\n[*] Generating text-based threat map...")
        
        self.cursor.execute('''
            SELECT station_name, station_address, COUNT(*) as hits, 
                   AVG(threat_level) as avg_threat,
                   GROUP_CONCAT(DISTINCT substr(timestamp, 1, 10)) as dates
            FROM detections 
            GROUP BY station_name, station_address
            ORDER BY hits DESC
        ''')
        
        stations = self.cursor.fetchall()
        
        if not stations:
            print("[*] No data for mapping")
            return
        
        # Create text-based map
        print("\n" + "="*70)
        print("THREAT MAP - Your Town")
        print("="*70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"Total Stations: {len(stations)}")
        print("="*70)
        
        for name, address, hits, threat, dates in stations:
            threat_level = int(threat) if threat else 0
            threat_stars = "★" * min(threat_level, 5)
            
            print(f"\n📍 {name}")
            print(f"   📍 Address: {address}")
            print(f"   ⚠️  Threat Level: {threat:.1f}/10 {threat_stars}")
            print(f"   📊 Detections: {hits}")
            print(f"   📅 Dates: {dates[:80]}...")
        
        # Summary statistics
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        self.cursor.execute('SELECT COUNT(DISTINCT station_name) FROM detections')
        unique_stations = self.cursor.fetchone()[0]
        
        self.cursor.execute('SELECT COUNT(*) FROM detections WHERE threat_level >= 7')
        high_threat = self.cursor.fetchone()[0]
        
        print(f"• Unique stations scanned: {unique_stations}")
        print(f"• High-threat detections (≥7/10): {high_threat}")
        print(f"• Total scans in database: {len(stations)}")
        
        # Create a simple HTML map for viewing in browser
        self._create_basic_html_map(stations)
    
    def _create_basic_html_map(self, stations):
        """Create a very basic HTML map without external dependencies"""
        try:
            html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Skimmer Sentinel - Threat Map</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .station {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high-threat {{ border-left: 5px solid #e74c3c; }}
        .medium-threat {{ border-left: 5px solid #f39c12; }}
        .low-threat {{ border-left: 5px solid #27ae60; }}
        .threat-badge {{ 
            display: inline-block; 
            padding: 3px 10px; 
            border-radius: 12px; 
            color: white;
            font-weight: bold;
            margin-right: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Skimmer Sentinel - Threat Map</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Total Stations: {len(stations)}</p>
    </div>
    
    <div class="legend">
        <h3>Threat Level Guide:</h3>
        <p><span class="threat-badge" style="background:#27ae60;">Low (0-3)</span>
           <span class="threat-badge" style="background:#f39c12;">Medium (4-6)</span>
           <span class="threat-badge" style="background:#e74c3c;">High (7-10)</span></p>
    </div>
'''
            
            for i, (name, address, hits, threat, dates) in enumerate(stations, 1):
                threat_level = int(threat) if threat else 0
                if threat_level >= 7:
                    threat_class = "high-threat"
                    threat_color = "#e74c3c"
                elif threat_level >= 4:
                    threat_class = "medium-threat"
                    threat_color = "#f39c12"
                else:
                    threat_class = "low-threat"
                    threat_color = "#27ae60"
                
                html_content += f'''
    <div class="station {threat_class}">
        <h3>#{i} {name}</h3>
        <p><strong>📍 Address:</strong> {address}</p>
        <p><strong>⚠️ Threat Level:</strong> 
            <span class="threat-badge" style="background:{threat_color};">{threat:.1f}/10</span>
            Detections: {hits}</p>
        <p><strong>📅 Dates:</strong> {dates[:100]}...</p>
    </div>
'''
            
            html_content += '''
    <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
        <h3>⚠️ Important Notice</h3>
        <p>This is a basic threat visualization. For interactive maps with GPS coordinates, 
        install the required dependencies:</p>
        <code>pip3 install folium pandas numpy</code>
        <p>Then run the MAP option in Skimmer Sentinel again.</p>
    </div>
</body>
</html>'''
            
            # Save the HTML file
            import os
            if not os.path.exists('exports'):
                os.makedirs('exports')
            
            map_file = f"exports/threat_map_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
            with open(map_file, 'w') as f:
                f.write(html_content)
            
            print(f"\n[+] Basic HTML map saved: {map_file}")
            print("[*] Open in web browser to view")
            
        except Exception as e:
            print(f"[!] Failed to create HTML map: {e}")
    
    def create_authority_report(self):
        """Generate professional report for law enforcement"""
        print("\n" + "="*70)
        print("LAW ENFORCEMENT REPORT GENERATOR")
        print("="*70)
        
        # Get date range
        days = input("[?] Report for how many days back? (default 30): ").strip()
        days = int(days) if days.isdigit() else 30
        
        # Query database
        self.cursor.execute('''
            SELECT station_name, station_address, COUNT(*) as incidents,
                   MAX(threat_level) as max_threat, 
                   GROUP_CONCAT(DISTINCT substr(timestamp, 1, 10)) as dates
            FROM detections 
            WHERE date(timestamp) >= date('now', ?)
            GROUP BY station_name, station_address
            HAVING COUNT(*) > 0
            ORDER BY incidents DESC
        ''', (f'-{days} days',))
        
        results = self.cursor.fetchall()
        
        if not results:
            print(f"[*] No incidents in last {days} days")
            return
        
        # Generate report
        report_id = f"LE-REPORT-{datetime.now().strftime('%Y%m%d')}"
        report_file = f"exports/{report_id}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("OFFICIAL SKIMMER DETECTION REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Report ID: {report_id}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Time Period: Last {days} days\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Stations Affected: {len(results)}\n")
            total_incidents = sum(r[2] for r in results)
            f.write(f"Total Incidents: {total_incidents}\n")
            f.write(f"Highest Threat Level: {max(r[3] for r in results)}/10\n\n")
            
            f.write("AFFECTED STATIONS (Priority Order)\n")
            f.write("-"*40 + "\n")
            
            for i, (name, addr, incidents, threat, dates) in enumerate(results, 1):
                f.write(f"\n{i}. {name}\n")
                f.write(f"   Address: {addr}\n")
                f.write(f"   Incidents: {incidents}\n")
                f.write(f"   Max Threat: {threat}/10\n")
                f.write(f"   Dates: {dates[:100]}...\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("RECOMMENDED ACTIONS\n")
            f.write("-"*40 + "\n")
            f.write("1. IMMEDIATE SURVEILLANCE of high-threat locations\n")
            f.write("2. NOTIFY station corporate security departments\n")
            f.write("3. COORDINATE with Secret Service (payment card fraud)\n")
            f.write("4. COMMUNITY ALERT for vulnerable populations\n")
            f.write("5. UNDERCOVER OPERATION during peak incident times\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("CONTACT\n")
            f.write("-"*40 + "\n")
            f.write("Local Police Non-Emergency\n")
            f.write("Secret Service Field Office: 206-622-0460 (Seattle)\n")
            f.write("FBI Cyber Task Force: 1-800-CALL-FBI\n")
            f.write("Report Compiled By: Community Sentinel Initiative\n")
        
        print(f"[+] Report saved: {report_file}")
        print("\n[*] DELIVERY INSTRUCTIONS:")
        print("    1. Print report")
        print("    2. Schedule meeting with police detective division")
        print("    3. Bring map visualization (exports/threat_map.html)")
        print("    4. Follow up in 48 hours")
    
    def deploy_countermeasures(self):
        """READ-ONLY countermeasures (for your protection)"""
        print("\n" + "="*70)
        print("COUNTERMEASURES (INFORMATION ONLY)")
        print("="*70)
        print("\n[*] LEGAL NOTE: These are defensive measures only.")
        print("    Never interfere with active skimmers.\n")
        
        print("DEFENSIVE ACTIONS AUTHORIZED:")
        print("1. VISUAL DETERRENTS")
        print("   - Post 'Skimmer Checked Daily' signs at pumps")
        print("   - Install tamper-evident security seals (available online)")
        print("   - Position visible security cameras on pumps")
        
        print("\n2. CUSTOMER EDUCATION")
        print("   - Create simple flyers for elderly residents")
        print("   - Teach: 'Wiggle the reader, check the seal'")
        print("   - Promote cash payment at high-risk stations")
        
        print("\n3. COMMUNITY ORGANIZING")
        print("   - Start neighborhood watch for gas stations")
        print("   - Coordinate with local businesses for alerts")
        print("   - Schedule volunteer patrols during high-risk times")
        
        print("\n[*] REMEMBER: Your role is evidence collection.")
        print("    Law enforcement's role is apprehension.")

def main():
    """Entry point with root check"""
    import os
    
    # Check for required directories
    for dir_name in ['data', 'exports', 'logs']:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"[+] Created directory: {dir_name}")
    
    if os.geteuid() != 0:
        print("[!] Run as root for Bluetooth access: sudo python3 sentinel.py")
        sys.exit(1)
    
    print("\n" + "="*70)
    print("SKIMMER SENTINEL INITIALIZING")
    print("="*70)
    print("[*] Hardware check...")
    print("[*] Loading modules...")
    print("[*] Database connected...")
    
    if not MAPPER_AVAILABLE:
        print("[!] WARNING: Advanced mapping requires folium")
        print("[*] You can still use all other features")
        print("[*] Install: pip3 install folium pandas numpy")
    
    print("[+] READY FOR DEPLOYMENT\n")
    
    sentinel = Sentinel()
    sentinel.mission_control()

if __name__ == "__main__":
    main()
