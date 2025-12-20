#!/usr/bin/env python3
"""
THREAT MAPPER v3.0 - Ultimate Skimmer Visualization
"""

import folium
from folium import plugins
import json
import sqlite3
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import os
from pathlib import Path

class ThreatMapper:
    def __init__(self, db_path='data/detections.db'):
        self.db_path = db_path
        
        # Threat color scheme - police ready
        self.threat_colors = {
            0: 'green',      # No threat
            1: 'lime',       # Minimal
            2: 'yellow',     # Low
            3: 'orange',     # Medium-Low
            4: 'darkorange', # Medium
            5: 'red',        # Medium-High
            6: 'darkred',    # High
            7: 'purple',     # Very High
            8: 'darkpurple', # Severe
            9: 'black',      # Critical
            10: 'black'      # Emergency
        }
    
    def get_detection_data(self, days_back=30):
        """Get detection data from database - smart and efficient"""
        conn = sqlite3.connect(self.db_path)
        
        # Smart query that gets everything we need
        query = '''
            SELECT 
                d.id,
                d.timestamp,
                d.station_name,
                d.station_address,
                d.gps_coords,
                d.threat_level,
                d.bluetooth_devices,
                d.notes,
                COALESCE(s.total_detections, 0) as station_detections
            FROM detections d
            LEFT JOIN stations s ON d.station_name = s.name
            WHERE date(d.timestamp) >= date('now', ?)
            ORDER BY d.timestamp DESC
        '''
        
        df = pd.read_sql_query(query, conn, params=(f'-{days_back} days',))
        conn.close()
        
        # Parse GPS coordinates if available
        if not df.empty:
            df['latitude'] = df['gps_coords'].apply(self._extract_coord, coord_type='lat')
            df['longitude'] = df['gps_coords'].apply(self._extract_coord, coord_type='lon')
        
        return df
    
    def _extract_coord(self, coord_str, coord_type='lat'):
        """Smart coordinate extraction"""
        if not coord_str or coord_str in ['GPS_COORDS_HERE', 'GPS_PENDING', 'UNKNOWN']:
            return None
        
        try:
            if ',' in coord_str:
                parts = coord_str.split(',')
                if len(parts) >= 2:
                    lat = float(parts[0].strip())
                    lon = float(parts[1].strip())
                    return lat if coord_type == 'lat' else lon
            return None
        except:
            return None
    
    def generate_map(self, stations=None):
        """
        MAIN MAP GENERATION - Called by Sentinel when user selects MAP option
        Creates the dopest, most useful map based on available data
        """
        print("\n" + "="*70)
        print("GENERATING THREAT VISUALIZATION")
        print("="*70)
        
        # Get data
        data_df = self.get_detection_data(days_back=30)
        
        if data_df.empty:
            print("[!] No detection data found in database")
            print("[*] Run some scans first (Options 1-3)")
            return "No data available for mapping"
        
        print(f"[+] Found {len(data_df)} detections")
        print(f"[+] {data_df['station_name'].nunique()} unique stations")
        
        # Ask user what type of map they want
        print("\n[+] SELECT MAP TYPE:")
        print("    1. INTERACTIVE CLUSTER MAP (Best for analysis)")
        print("    2. HEATMAP (Best for police patrol planning)")
        print("    3. QUICK MAP (Auto-selects best type)")
        
        choice = input("\n[?] Choice (1-3, default 3): ").strip()
        
        if choice == "1":
            map_obj = self._generate_cluster_map(data_df)
            map_type = "interactive"
        elif choice == "2":
            map_obj = self._generate_heatmap(data_df)
            map_type = "heatmap"
        else:
            # Auto-select based on data
            if len(data_df) > 20:
                map_obj = self._generate_heatmap(data_df)
                map_type = "heatmap"
            else:
                map_obj = self._generate_cluster_map(data_df)
                map_type = "cluster"
        
        if not map_obj:
            print("[!] Failed to generate map")
            return "Map generation failed"
        
        # Save the map
        exports_dir = Path('exports')
        exports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        map_file = exports_dir / f"skimmer_map_{timestamp}.html"
        map_obj.save(str(map_file))
        
        print(f"\n[✓] MAP GENERATED SUCCESSFULLY!")
        print(f"    File: {map_file}")
        print(f"    Type: {map_type.upper()} visualization")
        
        # Generate additional maps if requested
        generate_more = input("\n[?] Generate additional map types? (y/n): ").lower()
        if generate_more == 'y':
            self._generate_additional_maps(data_df, timestamp)
        
        # Show instructions
        self._show_usage_instructions(map_file, data_df)
        
        return str(map_file)
    
    def _generate_cluster_map(self, data_df):
        """Generate interactive cluster map with all the details"""
        print("\n[*] Creating interactive cluster map...")
        
        # Get center coordinates
        valid_coords = data_df[['latitude', 'longitude']].dropna()
        if valid_coords.empty:
            center_coords = [47.6062, -122.3321]  # Default center
            print("[*] Using default coordinates (enable GPS for accuracy)")
        else:
            center_coords = [valid_coords['latitude'].mean(), 
                           valid_coords['longitude'].mean()]
        
        # Create the map
        threat_map = folium.Map(
            location=center_coords,
            zoom_start=12,
            tiles='OpenStreetMap',
            control_scale=True
        )
        
        # Add marker cluster
        marker_cluster = plugins.MarkerCluster(
            name="Skimmer Detections",
            options={'maxClusterRadius': 40}
        ).add_to(threat_map)
        
        # Add individual markers
        detection_count = 0
        for _, row in data_df.dropna(subset=['latitude', 'longitude']).iterrows():
            detection_count += 1
            
            # Parse Bluetooth devices
            devices = []
            if row['bluetooth_devices']:
                try:
                    devices = json.loads(row['bluetooth_devices'])
                except:
                    devices = []
            
            # Create detailed popup
            popup_html = self._create_popup_html(row, devices)
            
            # Determine icon based on threat level
            threat_level = min(int(row['threat_level']), 10)
            icon_color = self.threat_colors.get(threat_level, 'gray')
            
            folium.Marker(
                location=[row['latitude'], row['longitude']],
                popup=folium.Popup(popup_html, max_width=350),
                icon=folium.Icon(
                    color=icon_color,
                    icon='exclamation-triangle' if threat_level >= 5 else 'info-circle',
                    prefix='fa'
                ),
                tooltip=f"{row['station_name']} - Threat: {threat_level}/10"
            ).add_to(marker_cluster)
        
        # Add heatmap as optional overlay if we have enough points
        if detection_count >= 5:
            heat_data = [[row['latitude'], row['longitude'], row['threat_level']] 
                        for _, row in data_df.dropna(subset=['latitude', 'longitude']).iterrows()]
            
            plugins.HeatMap(
                heat_data,
                name='Threat Heatmap',
                show=False,
                radius=20,
                blur=15,
                min_opacity=0.3,
                gradient={0.2: 'blue', 0.4: 'lime', 0.6: 'yellow', 0.8: 'orange', 1.0: 'red'}
            ).add_to(threat_map)
        
        # Add layer control
        folium.LayerControl().add_to(threat_map)
        
        # Add title and legend
        self._add_map_title(threat_map, "SKIMMER DETECTION CLUSTER MAP")
        self._add_legend(threat_map, detection_count)
        
        return threat_map
    
    def _generate_heatmap(self, data_df):
        """Generate heatmap showing threat hotspots"""
        print("\n[*] Creating threat heatmap...")
        
        # Get valid coordinates
        valid_coords = data_df[['latitude', 'longitude']].dropna()
        if valid_coords.empty:
            # Simulate coordinates if none available
            return self._generate_simulated_map(data_df)
        
        center_coords = [valid_coords['latitude'].mean(), 
                        valid_coords['longitude'].mean()]
        
        # Create heatmap with dark theme for better contrast
        threat_map = folium.Map(
            location=center_coords,
            zoom_start=13,
            tiles='CartoDB dark_matter',
            control_scale=True
        )
        
        # Add heatmap layer
        heat_data = [[row['latitude'], row['longitude'], row['threat_level']] 
                    for _, row in data_df.dropna(subset=['latitude', 'longitude']).iterrows()]
        
        plugins.HeatMap(
            heat_data,
            name='Skimmer Threat Heatmap',
            min_opacity=0.4,
            max_zoom=18,
            radius=25,
            blur=20,
            gradient={0.0: 'blue', 0.2: 'cyan', 0.4: 'lime', 0.6: 'yellow', 0.8: 'orange', 1.0: 'red'}
        ).add_to(threat_map)
        
        # Add some key markers for reference
        high_threat = data_df[data_df['threat_level'] >= 7].dropna(subset=['latitude', 'longitude'])
        if not high_threat.empty:
            for _, row in high_threat.head(10).iterrows():  # Limit to 10 markers
                folium.CircleMarker(
                    location=[row['latitude'], row['longitude']],
                    radius=8,
                    popup=f"<b>{row['station_name']}</b><br>Threat: {row['threat_level']}/10",
                    color='white',
                    fill=True,
                    fill_color='red',
                    fill_opacity=0.7,
                    weight=2
                ).add_to(threat_map)
        
        # Add title and legend
        self._add_map_title(threat_map, "SKIMMER THREAT HEATMAP")
        self._add_heatmap_legend(threat_map, len(data_df))
        
        return threat_map
    
    def _generate_simulated_map(self, data_df):
        """Generate map with simulated coordinates when GPS not available"""
        print("[*] No GPS coordinates found - creating simulated map")
        
        center_coords = [47.6062, -122.3321]  # Default center
        
        # Group by station
        station_data = data_df.groupby('station_name').agg({
            'threat_level': 'max',
            'station_address': 'first',
            'timestamp': 'count'
        }).reset_index()
        
        station_data['detection_count'] = station_data['timestamp']
        
        # Create map
        simulated_map = folium.Map(
            location=center_coords,
            zoom_start=12,
            tiles='OpenStreetMap'
        )
        
        # Add stations in a circle around center
        num_stations = len(station_data)
        if num_stations > 0:
            angles = np.linspace(0, 2*np.pi, num_stations, endpoint=False)
            radius = 0.015  # Smaller radius
            
            for i, (_, row) in enumerate(station_data.iterrows()):
                # Calculate position in circle
                lat = center_coords[0] + radius * np.cos(angles[i])
                lon = center_coords[1] + radius * np.sin(angles[i])
                
                threat_level = min(int(row['threat_level']), 10)
                color = self.threat_colors.get(threat_level, 'gray')
                
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=8 + min(row['detection_count'], 10),
                    popup=f"<b>{row['station_name']}</b><br>"
                          f"Address: {row['station_address']}<br>"
                          f"Threat: {threat_level}/10<br>"
                          f"Detections: {row['detection_count']}",
                    color=color,
                    fill=True,
                    fill_opacity=0.7
                ).add_to(simulated_map)
        
        # Add disclaimer
        disclaimer = '''
        <div style="position: fixed; bottom: 20px; left: 20px; width: 300px;
                    background: rgba(255,255,255,0.9); padding: 10px; border-radius: 5px;
                    border: 2px solid #ff6b6b; font-family: Arial; font-size: 12px;">
            <b>⚠️ NOTE: Simulated Locations</b><br>
            GPS coordinates not available. Enable GPS module for accurate mapping.
            Station positions are simulated for visualization.
        </div>
        '''
        simulated_map.get_root().html.add_child(folium.Element(disclaimer))
        
        self._add_map_title(simulated_map, "SKIMMER DETECTIONS (Simulated Locations)")
        
        return simulated_map
    
    def _create_popup_html(self, row, devices):
        """Create HTML popup for markers"""
        threat_level = min(int(row['threat_level']), 10)
        threat_color = self.threat_colors.get(threat_level, 'gray')
        
        # Format device list
        device_html = ""
        if devices:
            device_list = []
            for d in devices[:5]:  # Show first 5 devices
                name = d.get('name', 'Unknown')
                dev_threat = d.get('threat_level', 0)
                rssi = d.get('rssi', 'N/A')
                device_list.append(f"• {name} (Threat: {dev_threat}/10, RSSI: {rssi})")
            device_html = "<br>".join(device_list)
            if len(devices) > 5:
                device_html += f"<br>• ... and {len(devices) - 5} more"
        else:
            device_html = "No Bluetooth devices recorded"
        
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 320px;">
            <div style="background-color: {threat_color}; color: white; padding: 8px; border-radius: 5px 5px 0 0;">
                <h3 style="margin: 0; font-size: 16px;">{row['station_name']}</h3>
            </div>
            <div style="padding: 10px;">
                <p><b>📍 Address:</b><br>{row['station_address']}</p>
                <p><b>🕐 Time:</b> {row['timestamp'][:19]}</p>
                <p><b>⚠️ Threat Level:</b> <span style="color: {threat_color}; font-weight: bold;">
                    {threat_level}/10</span></p>
                <hr style="margin: 10px 0;">
                <p><b>📱 Detected Devices:</b><br>{device_html}</p>
                <hr style="margin: 10px 0;">
                <p style="font-size: 11px; color: #666;">
                ID: {row['id']}<br>
                Notes: {row['notes'][:100] if row['notes'] else 'None'}
                </p>
            </div>
        </div>
        """
    
    def _add_map_title(self, map_obj, title):
        """Add title to map"""
        title_html = f'''
        <div style="position: fixed; top: 10px; left: 50px; right: 50px; 
                    background: rgba(255,255,255,0.9); padding: 10px 20px;
                    border-radius: 5px; border: 2px solid #d9534f;
                    z-index: 9999; text-align: center; font-family: Arial;">
            <h2 style="margin: 5px 0; color: #d9534f;">{title}</h2>
            <p style="margin: 0; font-size: 12px;">
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | 
            Community Sentinel Initiative
            </p>
        </div>
        '''
        map_obj.get_root().html.add_child(folium.Element(title_html))
    
    def _add_legend(self, map_obj, detection_count):
        """Add legend to map"""
        legend_html = f'''
        <div style="position: fixed; bottom: 50px; left: 20px; width: 220px;
                    background: rgba(255,255,255,0.9); padding: 10px;
                    border-radius: 5px; border: 2px solid #666;
                    z-index: 9999; font-family: Arial; font-size: 12px;">
            <h4 style="margin-top: 0; color: #333;">THREAT LEGEND</h4>
            <div style="display: grid; grid-template-columns: 20px auto; gap: 5px; margin-bottom: 10px;">
                <div style="background: green; border-radius: 3px;"></div><div>0-2: Low</div>
                <div style="background: yellow; border-radius: 3px;"></div><div>3-4: Medium</div>
                <div style="background: orange; border-radius: 3px;"></div><div>5-6: High</div>
                <div style="background: red; border-radius: 3px;"></div><div>7-8: Severe</div>
                <div style="background: black; border-radius: 3px;"></div><div>9-10: Critical</div>
            </div>
            <hr style="margin: 10px 0;">
            <p style="margin: 5px 0;">
                <b>Total Detections:</b> {detection_count}<br>
                <b>Map Controls:</b><br>
                • Click markers for details<br>
                • Use layers button to toggle heatmap<br>
                • Zoom with mouse wheel
            </p>
        </div>
        '''
        map_obj.get_root().html.add_child(folium.Element(legend_html))
    
    def _add_heatmap_legend(self, map_obj, detection_count):
        """Add heatmap-specific legend"""
        legend_html = f'''
        <div style="position: fixed; bottom: 50px; left: 20px; width: 250px;
                    background: rgba(0,0,0,0.7); color: white; padding: 10px;
                    border-radius: 5px; border: 2px solid #ff6b6b;
                    z-index: 9999; font-family: Arial; font-size: 12px;">
            <h4 style="margin-top: 0; color: #ff6b6b;">THREAT HEATMAP</h4>
            <div style="background: linear-gradient(to right, 
                    blue, cyan, lime, yellow, orange, red);
                    height: 20px; width: 100%; margin: 5px 0; border-radius: 3px;"></div>
            <div style="display: flex; justify-content: space-between; font-size: 10px;">
                <span>Low Threat</span><span>High Threat</span>
            </div>
            <hr style="margin: 10px 0; border-color: #555;">
            <p style="margin: 5px 0; font-size: 11px;">
                <b>🔴 Hotspots</b> = High skimmer activity<br>
                <b>🟡 Warm areas</b> = Moderate activity<br>
                <b>🟢 Cool areas</b> = Low/no activity<br><br>
                <b>Total scans:</b> {detection_count}<br>
                <b>Perfect for police patrol planning</b>
            </p>
        </div>
        '''
        map_obj.get_root().html.add_child(folium.Element(legend_html))
    
    def _generate_additional_maps(self, data_df, timestamp):
        """Generate additional map types if user wants them"""
        print("\n[*] Generating additional map types...")
        
        exports_dir = Path('exports')
        exports_dir.mkdir(exist_ok=True)
        
        # Generate printable map
        printable_map = self._generate_printable_map(data_df)
        if printable_map:
            printable_file = exports_dir / f"skimmer_printable_{timestamp}.html"
            printable_map.save(str(printable_file))
            print(f"[+] Printable map: {printable_file}")
        
        # Generate timeline map if we have enough temporal data
        if len(data_df) >= 10:
            timeline_map = self._generate_timeline_map(data_df)
            if timeline_map:
                timeline_file = exports_dir / f"skimmer_timeline_{timestamp}.html"
                timeline_map.save(str(timeline_file))
                print(f"[+] Timeline map: {timeline_file}")
    
    def _generate_printable_map(self, data_df):
        """Generate printer-friendly map"""
        if data_df.empty:
            return None
        
        # Get center
        valid_coords = data_df[['latitude', 'longitude']].dropna()
        if valid_coords.empty:
            center_coords = [47.6062, -122.3321]
        else:
            center_coords = [valid_coords['latitude'].mean(), 
                           valid_coords['longitude'].mean()]
        
        # Simple, high-contrast map for printing
        printable_map = folium.Map(
            location=center_coords,
            zoom_start=13,
            tiles='Stamen Toner'  # Best for black & white printing
        )
        
        # Add numbered markers
        stations = data_df['station_name'].unique()[:20]  # Limit to 20 stations
        
        for i, station in enumerate(stations, 1):
            station_data = data_df[data_df['station_name'] == station]
            if not station_data.empty:
                row = station_data.iloc[0]
                if pd.notna(row['latitude']) and pd.notna(row['longitude']):
                    folium.Marker(
                        location=[row['latitude'], row['longitude']],
                        popup=f"<b>{i}. {station}</b><br>Max Threat: {row['threat_level']}/10",
                        icon=folium.DivIcon(
                            html=f'<div style="font-family: Arial; font-weight: bold; '
                                 f'font-size: 14px; color: white; background-color: #d9534f; '
                                 f'border-radius: 50%; width: 24px; height: 24px; '
                                 f'text-align: center; line-height: 24px;">{i}</div>'
                        )
                    ).add_to(printable_map)
        
        return printable_map
    
    def _generate_timeline_map(self, data_df):
        """Generate animated timeline map"""
        if data_df.empty:
            return None
        
        # Sort by time
        data_df = data_df.sort_values('timestamp')
        
        # Get center
        valid_coords = data_df[['latitude', 'longitude']].dropna()
        if valid_coords.empty:
            return None
        
        center_coords = [valid_coords['latitude'].mean(), 
                        valid_coords['longitude'].mean()]
        
        timeline_map = folium.Map(
            location=center_coords,
            zoom_start=12,
            tiles='OpenStreetMap'
        )
        
        # Create timeline features
        features = []
        for _, row in data_df.dropna(subset=['latitude', 'longitude']).iterrows():
            feature = {
                'type': 'Feature',
                'geometry': {
                    'type': 'Point',
                    'coordinates': [row['longitude'], row['latitude']]
                },
                'properties': {
                    'time': row['timestamp'],
                    'popup': f"{row['station_name']}<br>Threat: {row['threat_level']}/10",
                    'icon': 'circle',
                    'iconstyle': {
                        'fillColor': self.threat_colors.get(min(int(row['threat_level']), 10), 'gray'),
                        'fillOpacity': 0.7,
                        'stroke': False,
                        'radius': 5 + min(row['threat_level'], 5)
                    }
                }
            }
            features.append(feature)
        
        # Add timeline
        plugins.TimestampedGeoJson(
            {
                'type': 'FeatureCollection',
                'features': features
            },
            period='P3D',  # 3-day periods
            add_last_point=True,
            auto_play=False,
            loop=False,
            max_speed=2,
            loop_button=True,
            date_options='YYYY-MM-DD',
            time_slider_drag_update=True
        ).add_to(timeline_map)
        
        return timeline_map
    
    def _show_usage_instructions(self, map_file, data_df):
        """Show user how to use the map"""
        print("\n" + "="*70)
        print("MAP READY - INSTRUCTIONS FOR USE")
        print("="*70)
        
        high_threat = len(data_df[data_df['threat_level'] >= 7])
        total_stations = data_df['station_name'].nunique()
        
        print(f"\n YOUR DATA SUMMARY:")
        print(f"   • Total detections: {len(data_df)}")
        print(f"   • Stations affected: {total_stations}")
        print(f"   • High-threat alerts (≥7/10): {high_threat}")
        
        print(f"\n HOW TO VIEW YOUR MAP:")
        print(f"   1. Open this file in web browser: {map_file}")
        print(f"   2. CLICK on any marker for details")
        print(f"   3. Use mouse wheel to ZOOM in/out")
        print(f"   4. Click-drag to PAN around map")
        
        print(f"\n FOR POLICE BRIEFINGS:")
        print(f"   1. Show HEATMAP view (red = high threat areas)")
        print(f"   2. Use 'Print to PDF' for handouts")
        print(f"   3. Bring laptop for interactive demo")
        print(f"   4. Focus patrols on RED zones")
        
        print(f"\n FILES SAVED IN: exports/")
        print(f"   Open with: firefox {map_file}  # or chrome, etc.")


# Quick standalone test
if __name__ == "__main__":
    print("\n" + "="*70)
    print("THREAT MAPPER STANDALONE TEST")
    print("="*70)
    
    mapper = ThreatMapper()
    
    if not os.path.exists('data/detections.db'):
        print("\n[!] Database not found at data/detections.db")
        print("[*] Run Sentinel first to collect some data")
        print("[*] Try: sudo python3 sentinel.py")
    else:
        print("\n[*] Database found, testing mapper...")
        result = mapper.generate_map()
        print(f"\n[+] Result: {result}")
